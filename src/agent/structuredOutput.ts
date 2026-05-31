import type { Finding } from "../shared/types.js";

export type ModelExplanation = {
  title: string;
  impact: string;
  evidenceSummary: string;
  suggestedFix: string;
  confidenceReason: string;
  safeNextSteps: string[];
  cveUsage: "from_evidence" | "not_applicable" | "not_present";
};

export type ExplanationValidationResult =
  | { ok: true; explanation: ModelExplanation; violations: [] }
  | { ok: false; explanation: ModelExplanation; violations: string[] };

const cvePattern = /\bCVE-\d{4}-\d{4,8}\b/gi;
const ghsaPattern = /\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/gi;
const osvPattern = /\b(?:OSV|PYSEC|GO|RUSTSEC)-\d{4}-\d+\b/gi;
const pathPattern = /(?:[A-Za-z]:\\|\.{1,2}[\\/]|[A-Za-z0-9_.-]+[\\/])(?:[A-Za-z0-9_.@()+-]+[\\/])*[A-Za-z0-9_.@()+-]+\.[A-Za-z0-9]{1,12}\b/g;
const linePattern = /\bline\s+(\d{1,8})\b/gi;
const unsafeRemediationPattern = /\b(?:exploit|payload|reverse shell|curl\s+[^|]+\|\s*sh|wget\s+[^|]+\|\s*sh|npm\s+install|pnpm\s+install|yarn\s+install|bun\s+install|pip\s+install)\b/gi;
const genericPackageWords = new Set([
  "audit",
  "dependency",
  "dependencies",
  "ecosystem",
  "file",
  "files",
  "json",
  "lock",
  "lockfile",
  "manifest",
  "manager",
  "metadata",
  "name",
  "registry",
  "release",
  "source",
  "version",
  "versions",
]);

export function parseModelExplanation(raw: string): ModelExplanation | undefined {
  try {
    const parsed = JSON.parse(raw) as Partial<ModelExplanation>;
    if (!parsed.title || !parsed.impact || !parsed.evidenceSummary || !parsed.suggestedFix) {
      return undefined;
    }
    return normalizeExplanation(parsed);
  } catch {
    return undefined;
  }
}

export function validateModelExplanation(
  finding: Finding,
  explanation: ModelExplanation
): ExplanationValidationResult {
  const normalized = normalizeExplanation(explanation);
  const violations: string[] = [];
  const text = explanationText(normalized);
  const allowed = collectAllowedEvidence(finding);

  for (const cve of uniqueMatches(text, cvePattern)) {
    if (!allowed.identifiers.has(cve.toUpperCase())) {
      violations.push(`invented CVE identifier: ${cve}`);
    }
  }
  for (const ghsa of uniqueMatches(text, ghsaPattern)) {
    if (!allowed.identifiers.has(ghsa.toUpperCase())) {
      violations.push(`invented GHSA identifier: ${ghsa}`);
    }
  }
  for (const osv of uniqueMatches(text, osvPattern)) {
    if (!allowed.identifiers.has(osv.toUpperCase())) {
      violations.push(`invented OSV identifier: ${osv}`);
    }
  }
  for (const filePath of uniqueMatches(text, pathPattern)) {
    const normalizedPath = filePath.replace(/\\/g, "/");
    if (!allowed.files.has(normalizedPath)) {
      violations.push(`invented file path: ${filePath}`);
    }
  }
  for (const line of uniqueLineMatches(text)) {
    if (!allowed.lines.has(line)) {
      violations.push(`invented line number: ${line}`);
    }
  }
  for (const packageName of allowed.disallowedPackageMentions(text)) {
    violations.push(`invented package name: ${packageName}`);
  }

  normalized.suggestedFix = clampUnsafeRemediation(normalized.suggestedFix);
  normalized.safeNextSteps = normalized.safeNextSteps.map(clampUnsafeRemediation);

  return violations.length === 0
    ? { ok: true, explanation: normalized, violations: [] }
    : { ok: false, explanation: normalized, violations };
}

export function normalizeExplanation(value: Partial<ModelExplanation>): ModelExplanation {
  return {
    title: clamp(value.title ?? "Scanner finding"),
    impact: clamp(value.impact ?? "Review the scanner evidence for impact."),
    evidenceSummary: clamp(value.evidenceSummary ?? "Explanation was not available.", 900),
    suggestedFix: clampUnsafeRemediation(clamp(value.suggestedFix ?? "Review and remediate according to the scanner guidance.", 900)),
    confidenceReason: clamp(value.confidenceReason ?? "Confidence is based only on supplied scanner evidence.", 700),
    safeNextSteps: (value.safeNextSteps ?? ["Review scanner evidence.", "Apply the minimal safe fix.", "Run Hermsec again."])
      .slice(0, 6)
      .map((step) => clampUnsafeRemediation(clamp(step, 240))),
    cveUsage: value.cveUsage ?? "not_present"
  };
}

function collectAllowedEvidence(finding: Finding): {
  identifiers: Set<string>;
  files: Set<string>;
  lines: Set<number>;
  disallowedPackageMentions(text: string): string[];
} {
  const identifiers = new Set<string>();
  for (const value of finding.identifiers?.cve ?? []) {
    identifiers.add(value.toUpperCase());
  }
  for (const value of finding.identifiers?.ghsa ?? []) {
    identifiers.add(value.toUpperCase());
  }
  for (const value of finding.identifiers?.osv ?? []) {
    identifiers.add(value.toUpperCase());
  }

  const files = new Set<string>();
  if (finding.location?.file) {
    files.add(finding.location.file.replace(/\\/g, "/"));
  }

  const lines = new Set<number>();
  if (finding.location?.startLine !== undefined) {
    lines.add(finding.location.startLine);
  }
  if (finding.location?.endLine !== undefined) {
    lines.add(finding.location.endLine);
  }

  const knownPackage = finding.package?.name;
  return {
    identifiers,
    files,
    lines,
    disallowedPackageMentions(text: string): string[] {
      const mentions = packageMentionCandidates(text);
      return mentions
        .filter((mention) => !isGenericPackageWord(mention.packageName))
        .filter((mention) => !knownPackage || mention.packageName.toLowerCase() !== knownPackage.toLowerCase())
        .map((mention) => mention.raw);
    }
  };
}

function explanationText(value: ModelExplanation): string {
  return [
    value.title,
    value.impact,
    value.evidenceSummary,
    value.suggestedFix,
    value.confidenceReason,
    ...value.safeNextSteps
  ].join("\n");
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  const matches = new Set<string>();
  for (const match of text.matchAll(pattern)) {
    matches.add(match[0]);
  }
  return [...matches].sort((left, right) => left.localeCompare(right));
}

function uniqueLineMatches(text: string): number[] {
  const matches = new Set<number>();
  for (const match of text.matchAll(linePattern)) {
    const value = Number(match[1]);
    if (Number.isFinite(value)) {
      matches.add(value);
    }
  }
  return [...matches].sort((left, right) => left - right);
}

function packageMentionCandidates(text: string): Array<{ raw: string; packageName: string }> {
  const matches = new Map<string, { raw: string; packageName: string }>();
  const pattern = /\bpackage\s+["'`]?(@?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?)["'`]?\b/gi;
  for (const match of text.matchAll(pattern)) {
    const raw = match[0];
    const packageName = match[1];
    if (!packageName) {
      continue;
    }
    const key = raw.toLowerCase();
    if (!matches.has(key)) {
      matches.set(key, { raw, packageName });
    }
  }
  return [...matches.values()].sort((left, right) => left.raw.localeCompare(right.raw));
}

function isGenericPackageWord(packageName: string): boolean {
  return genericPackageWords.has(packageName.toLowerCase());
}

function clampUnsafeRemediation(value: string): string {
  return value.replace(unsafeRemediationPattern, "use a project-approved defensive remediation step");
}

function clamp(value: string, max = 300): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length > max ? `${compact.slice(0, max - 3)}...` : compact;
}
