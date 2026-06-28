import type { CodeInspectionRuntime, FileSnippet } from "./codeInspection.js";
import type { Finding } from "../shared/types.js";

export type EvidenceSourceCandidate = {
  candidateId: string;
  finding: Finding;
};

export type EvidenceRevalidationInput = {
  finding: Finding;
  runtime: CodeInspectionRuntime;
  sourceCandidates?: readonly EvidenceSourceCandidate[];
  requireKnownSourceIds?: boolean;
};

export type EvidenceRevalidationResult =
  | { ok: true; finding: Finding; snippet: FileSnippet; reasons: [] }
  | { ok: false; reasons: string[] };

const cvePattern = /\bCVE-\d{4}-\d{4,8}\b/gi;
const ghsaPattern = /\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/gi;
const osvPattern = /\b(?:OSV|PYSEC|GO|RUSTSEC)-\d{4}-\d+\b/gi;
const cwePattern = /\bCWE-\d{1,6}\b/gi;
const pathPattern = /(?:[A-Za-z]:\\|\.{1,2}[\\/]|[A-Za-z0-9_.@()-]+[\\/])(?:[A-Za-z0-9_.@()+-]+[\\/])*[A-Za-z0-9_.@()+-]+\.[A-Za-z0-9]{1,12}\b/g;
const linePattern = /\bline\s+(\d{1,8})\b/gi;
const findingIdPattern = /\bfinding\s+id\s+["'`]?([A-Za-z0-9_.:-]+)["'`]?\b/gi;
const quotedFindingIdPattern = /["'`]([A-Za-z0-9_.:-]*finding[A-Za-z0-9_.:-]*)["'`]/gi;
const candidateIdPattern = /\bcandidate\s+id\s+["'`]?([A-Za-z0-9_.:-]+)["'`]?\b/gi;
const quotedCandidateIdPattern = /["'`]([A-Za-z0-9_.:-]*candidate[A-Za-z0-9_.:-]*)["'`]/gi;

const genericScannerWords = new Set([
  "analysis",
  "data",
  "evidence",
  "finding",
  "findings",
  "output",
  "report",
  "reported",
  "rule",
  "rules",
  "scanner",
  "scanners",
  "the",
  "this",
  "tool",
  "tools",
]);

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

const ignoredApiTerms = new Set([
  "allowlist",
  "calls",
  "finding",
  "fix",
  "line",
  "parser",
  "reported",
  "review",
  "source",
  "use",
  "uses",
]);

const apiSignalPatterns: Array<{ cwe: string; patterns: RegExp[] }> = [
  { cwe: "CWE-95", patterns: [/\beval\s*\(/i, /\bFunction\s*\(/, /\bexec\s*\(/i] },
  { cwe: "CWE-78", patterns: [/\bchild_process\b/i, /\bspawn\s*\(/i, /\bexecFile\s*\(/i, /\bexec\s*\(/i, /\bos\.system\s*\(/i, /\bsubprocess\./i, /\bshell\s*[:=]\s*true\b/i, /\bshell=True\b/i] },
  { cwe: "CWE-89", patterns: [/\bSELECT\b/i, /\brawQuery\s*\(/i, /\bwhereRaw\s*\(/i, /\bquery\s*\(/i, /\bexecute\s*\(/i] },
  { cwe: "CWE-79", patterns: [/\binnerHTML\b/i, /\bdangerouslySetInnerHTML\b/i, /\bres\.send\s*\(/i, /\bwrite\s*\(/i] },
  { cwe: "CWE-502", patterns: [/\bpickle\.loads\s*\(/i, /\byaml\.load\s*\(/i, /\bdeserialize\b/i] },
  { cwe: "CWE-798", patterns: [/\bapi[_-]?key\b/i, /\bsecret\b/i, /\btoken\b/i, /\bpassword\b/i] },
  { cwe: "CWE-489", patterns: [/\bdebug\s*=\s*true\b/i, /\bDEBUG\s*=\s*True\b/] },
  { cwe: "CWE-295", patterns: [/\brejectUnauthorized\s*:\s*false\b/i, /\bverify\s*=\s*false\b/i] },
  { cwe: "CWE-829", patterns: [/\bpostinstall\b/i, /\bpreinstall\b/i, /\bcurl\b.*\|\s*sh\b/i, /\bwget\b.*\|\s*sh\b/i, /\bADD\s+https?:\/\//i] },
  { cwe: "CWE-942", patterns: [/\bAccess-Control-Allow-Origin\b/i, /\bcors\s*\(/i] },
];

const sensitiveApiTerms = [
  "eval",
  "Function",
  "exec",
  "execFile",
  "spawn",
  "child_process",
  "subprocess",
  "os.system",
  "pickle.loads",
  "yaml.load",
  "jwt.verify",
  "innerHTML",
  "dangerouslySetInnerHTML",
  "rawQuery",
  "whereRaw",
  "query",
  "execute",
  "SELECT",
  "redirect",
  "cors",
  "getParameter",
  "getHeader",
  "InitialDirContext",
  "XPath",
];

export async function revalidateProductFindingEvidence(input: EvidenceRevalidationInput): Promise<EvidenceRevalidationResult> {
  const reasons: string[] = [];
  const finding = input.finding;
  const sourceIds = finding.agent?.sourceFindingIds ?? [];
  const allKnown = collectKnownEvidence(input.sourceCandidates ?? []);
  const cited = collectKnownEvidence(selectCitedCandidates(input.sourceCandidates ?? [], sourceIds));
  const claimText = findingClaimText(finding);

  if (input.requireKnownSourceIds) {
    if (sourceIds.length === 0) {
      reasons.push("finding did not cite known source candidate IDs");
    }
  }
  if (sourceIds.length > 0) {
    for (const sourceId of sourceIds) {
      if (!allKnown.candidateIds.has(sourceId)) {
        reasons.push(`unknown source candidate ID: ${sourceId}`);
      }
    }
  }

  const candidateIds = finding.agent?.candidateIds ?? [];
  for (const candidateId of candidateIdsInText(claimText)) {
    if (!allKnown.candidateIds.has(candidateId) && !candidateIds.includes(candidateId)) {
      reasons.push(`unknown candidate ID claim: ${candidateId}`);
    }
  }
  for (const findingId of findingIdsInText(claimText)) {
    if (!allKnown.findingIds.has(findingId) && !allKnown.candidateIds.has(findingId) && findingId !== finding.id && findingId !== finding.fingerprint) {
      reasons.push(`unknown finding ID claim: ${findingId}`);
    }
  }
  for (const scannerId of scannerMentionCandidates(claimText)) {
    if (!cited.scannerIds.has(scannerId.toLowerCase())) {
      reasons.push(`unknown scanner ID claim: ${scannerId}`);
    }
  }

  let exactSnippet: FileSnippet | undefined;
  let nearbySnippet: FileSnippet | undefined;
  if (!finding.location?.file) {
    reasons.push("finding is missing a repository file");
  } else {
    try {
      exactSnippet = await input.runtime.readFileSnippet({
        path: finding.location.file,
        startLine: finding.location.startLine ?? 1,
        endLine: finding.location.endLine ?? finding.location.startLine ?? 1,
        contextLines: 0,
        maxChars: 4_000,
      });
      if (finding.location.startLine !== undefined && exactSnippet.startLine !== finding.location.startLine) {
        reasons.push(`line ${finding.location.startLine} does not exist in ${finding.location.file}`);
      }
      if (finding.location.endLine !== undefined && exactSnippet.endLine < finding.location.endLine) {
        reasons.push(`line ${finding.location.endLine} does not exist in ${finding.location.file}`);
      }
      if (!exactSnippet.text.trim()) {
        reasons.push(`evidence snippet is empty for ${finding.location.file}`);
      }
    } catch (error) {
      reasons.push(`file evidence is not readable in repo: ${shortError(error)}`);
    }

    if (exactSnippet) {
      nearbySnippet = await input.runtime.readFileSnippet({
        path: exactSnippet.file,
        startLine: finding.location.startLine ?? exactSnippet.startLine,
        endLine: finding.location.endLine ?? finding.location.startLine ?? exactSnippet.endLine,
        contextLines: 4,
        maxChars: 8_000,
      });
    }
  }

  const snippetText = nearbySnippet?.text ?? exactSnippet?.text ?? "";
  const localCwes = inferCwesFromSnippet(snippetText);
  const allowedFiles = new Set([finding.location?.file, ...cited.files].filter((value): value is string => Boolean(value)));
  const allowedLines = new Set([
    finding.location?.startLine,
    finding.location?.endLine,
    ...cited.lines,
  ].filter((value): value is number => value !== undefined));

  for (const filePath of uniqueMatches(claimText, pathPattern)) {
    const normalized = filePath.replace(/\\/g, "/");
    if (!allowedFiles.has(normalized)) {
      reasons.push(`unsupported file path claim: ${filePath}`);
    }
  }
  for (const line of lineClaims(claimText)) {
    if (allowedLines.size > 0 && !allowedLines.has(line)) {
      reasons.push(`unsupported line claim: ${line}`);
    }
  }

  for (const cve of identifierClaims(finding, claimText, "cve")) {
    if (!cited.identifiers.has(cve.toUpperCase()) && !containsTerm(snippetText, cve)) {
      reasons.push(`unsupported CVE claim: ${cve}`);
    }
  }
  for (const ghsa of identifierClaims(finding, claimText, "ghsa")) {
    if (!cited.identifiers.has(ghsa.toUpperCase()) && !containsTerm(snippetText, ghsa)) {
      reasons.push(`unsupported GHSA claim: ${ghsa}`);
    }
  }
  for (const osv of identifierClaims(finding, claimText, "osv")) {
    if (!cited.identifiers.has(osv.toUpperCase()) && !containsTerm(snippetText, osv)) {
      reasons.push(`unsupported OSV claim: ${osv}`);
    }
  }
  for (const cwe of cweClaims(finding, claimText)) {
    const normalized = cwe.toUpperCase();
    if (!cited.cwes.has(normalized) && !localCwes.has(normalized) && !containsTerm(snippetText, normalized)) {
      reasons.push(`unsupported CWE claim: ${cwe}`);
    }
  }
  for (const packageName of packageClaims(finding, claimText)) {
    if (!cited.packages.has(packageName.toLowerCase()) && !containsTerm(snippetText, packageName)) {
      reasons.push(`unsupported package claim: ${packageName}`);
    }
  }

  const missingApiTerms = sourceSinkApiClaims(finding)
    .filter((term) => !containsTerm(snippetText, term));
  for (const term of missingApiTerms) {
    reasons.push(`source/sink/API text is not near evidence: ${term}`);
  }

  return reasons.length === 0 && exactSnippet
    ? { ok: true, finding, snippet: exactSnippet, reasons: [] }
    : { ok: false, reasons: [...new Set(reasons)] };
}

function selectCitedCandidates(
  candidates: readonly EvidenceSourceCandidate[],
  sourceIds: readonly string[],
): EvidenceSourceCandidate[] {
  if (sourceIds.length === 0) {
    return [];
  }
  const ids = new Set(sourceIds);
  return candidates.filter((candidate) => ids.has(candidate.candidateId));
}

function collectKnownEvidence(candidates: readonly EvidenceSourceCandidate[]): {
  candidateIds: Set<string>;
  findingIds: Set<string>;
  scannerIds: Set<string>;
  identifiers: Set<string>;
  cwes: Set<string>;
  packages: Set<string>;
  files: Set<string>;
  lines: Set<number>;
} {
  const candidateIds = new Set<string>();
  const findingIds = new Set<string>();
  const scannerIds = new Set<string>();
  const identifiers = new Set<string>();
  const cwes = new Set<string>();
  const packages = new Set<string>();
  const files = new Set<string>();
  const lines = new Set<number>();

  for (const candidate of candidates) {
    const finding = candidate.finding;
    candidateIds.add(candidate.candidateId);
    for (const id of finding.agent?.candidateIds ?? []) {
      candidateIds.add(id);
    }
    findingIds.add(finding.id);
    findingIds.add(finding.fingerprint);
    addLower(scannerIds, finding.tool);
    addLower(scannerIds, finding.ruleId);
    addLower(scannerIds, finding.agent?.role);
    for (const value of finding.identifiers?.cve ?? []) {
      identifiers.add(value.toUpperCase());
    }
    for (const value of finding.identifiers?.ghsa ?? []) {
      identifiers.add(value.toUpperCase());
    }
    for (const value of finding.identifiers?.osv ?? []) {
      identifiers.add(value.toUpperCase());
    }
    for (const cwe of finding.cwe ?? []) {
      cwes.add(cwe.toUpperCase());
    }
    if (finding.package?.name) {
      packages.add(finding.package.name.toLowerCase());
    }
    if (finding.location?.file) {
      files.add(finding.location.file.replace(/\\/g, "/"));
    }
    if (finding.location?.startLine !== undefined) {
      lines.add(finding.location.startLine);
    }
    if (finding.location?.endLine !== undefined) {
      lines.add(finding.location.endLine);
    }
  }

  return { candidateIds, findingIds, scannerIds, identifiers, cwes, packages, files, lines };
}

function findingClaimText(finding: Finding): string {
  return [
    finding.title,
    finding.description,
    finding.evidence,
    finding.remediation,
    finding.tool,
    finding.ruleId,
    ...(finding.cwe ?? []),
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
    finding.package?.name,
    finding.package?.installedVersion,
  ].filter((value): value is string => Boolean(value)).join("\n");
}

function identifierClaims(finding: Finding, text: string, kind: "cve" | "ghsa" | "osv"): string[] {
  const values = new Set<string>();
  const fieldValues = kind === "cve"
    ? finding.identifiers?.cve
    : kind === "ghsa"
      ? finding.identifiers?.ghsa
      : finding.identifiers?.osv;
  for (const value of fieldValues ?? []) {
    values.add(value);
  }
  const pattern = kind === "cve" ? cvePattern : kind === "ghsa" ? ghsaPattern : osvPattern;
  for (const value of uniqueMatches(text, pattern)) {
    values.add(value);
  }
  return [...values].sort((left, right) => left.localeCompare(right));
}

function cweClaims(finding: Finding, text: string): string[] {
  return [...new Set([...(finding.cwe ?? []), ...uniqueMatches(text, cwePattern)])]
    .sort((left, right) => left.localeCompare(right));
}

function packageClaims(finding: Finding, text: string): string[] {
  const packages = new Set<string>();
  if (finding.package?.name) {
    packages.add(finding.package.name);
  }
  for (const mention of packageMentionCandidates(text)) {
    if (!genericPackageWords.has(mention.packageName.toLowerCase())) {
      packages.add(mention.packageName);
    }
  }
  return [...packages].sort((left, right) => left.localeCompare(right));
}

function packageMentionCandidates(text: string): Array<{ raw: string; packageName: string }> {
  const matches = new Map<string, { raw: string; packageName: string }>();
  const patterns = [
    /\bpackage\s+["'`]?(@?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?)["'`]?\b/gi,
    /\bdependency\s+["'`]?(@?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?)["'`]?\b/gi,
    /\bmodule\s+["'`]?(@?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?)["'`]?\b/gi,
  ];
  for (const pattern of patterns) {
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
  }
  return [...matches.values()].sort((left, right) => left.raw.localeCompare(right.raw));
}

function sourceSinkApiClaims(finding: Finding): string[] {
  const text = [
    finding.title,
    finding.description,
    finding.evidence,
    finding.ruleId,
  ].filter(Boolean).join("\n");
  const terms = new Set<string>();

  for (const match of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
    const term = match[1];
    if (term && !ignoredApiTerms.has(term.toLowerCase())) {
      terms.add(term);
    }
  }
  for (const match of text.matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\b/g)) {
    const term = match[1];
    if (term && sensitiveApiTerms.some((api) => api.toLowerCase() === term.toLowerCase())) {
      terms.add(term);
    }
  }
  for (const api of sensitiveApiTerms) {
    if (containsTerm(text, api)) {
      terms.add(api);
    }
  }

  return [...terms].sort((left, right) => left.localeCompare(right));
}

function inferCwesFromSnippet(text: string): Set<string> {
  const cwes = new Set<string>();
  for (const signal of apiSignalPatterns) {
    if (signal.patterns.some((pattern) => pattern.test(text))) {
      cwes.add(signal.cwe);
    }
  }
  return cwes;
}

function scannerMentionCandidates(text: string): string[] {
  const scanners = new Set<string>();
  const patterns = [
    /\b(?:scanner|tool)\s+id\s+["'`]?([A-Za-z0-9_.-]+)["'`]?\b/gi,
    /\b(?:scanner|tool)\s+["'`]([A-Za-z0-9_.-]+)["'`]/gi,
    /\b(?:reported|found|confirmed)\s+by\s+([A-Za-z0-9_.-]+)\b/gi,
    /\bfrom\s+([A-Za-z0-9_.-]+)\s+(?:scanner|tool)\b/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const value = match[1];
      if (value && !genericScannerWords.has(value.toLowerCase())) {
        scanners.add(value);
      }
    }
  }
  return [...scanners].sort((left, right) => left.localeCompare(right));
}

function findingIdsInText(text: string): string[] {
  const ids = new Set<string>();
  for (const match of text.matchAll(findingIdPattern)) {
    if (match[1]) {
      ids.add(match[1]);
    }
  }
  for (const match of text.matchAll(quotedFindingIdPattern)) {
    if (match[1]) {
      ids.add(match[1]);
    }
  }
  return [...ids].sort((left, right) => left.localeCompare(right));
}

function candidateIdsInText(text: string): string[] {
  const ids = new Set<string>();
  for (const match of text.matchAll(candidateIdPattern)) {
    if (match[1]) {
      ids.add(match[1]);
    }
  }
  for (const match of text.matchAll(quotedCandidateIdPattern)) {
    if (match[1]) {
      ids.add(match[1]);
    }
  }
  return [...ids].sort((left, right) => left.localeCompare(right));
}

function lineClaims(text: string): number[] {
  const lines = new Set<number>();
  for (const match of text.matchAll(linePattern)) {
    const value = Number(match[1]);
    if (Number.isInteger(value)) {
      lines.add(value);
    }
  }
  for (const match of text.matchAll(/(?:[A-Za-z0-9_.@()+-]+[\\/])+[A-Za-z0-9_.@()+-]+\.[A-Za-z0-9]{1,12}:(\d{1,8})\b/g)) {
    const value = Number(match[1]);
    if (Number.isInteger(value)) {
      lines.add(value);
    }
  }
  return [...lines].sort((left, right) => left - right);
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  const matches = new Set<string>();
  for (const match of text.matchAll(pattern)) {
    matches.add(match[0]);
  }
  return [...matches].sort((left, right) => left.localeCompare(right));
}

function containsTerm(text: string, term: string): boolean {
  const haystack = normalizeText(text);
  const needle = normalizeText(term);
  if (!needle) {
    return false;
  }
  if (/^[a-z0-9_]+$/i.test(needle)) {
    return new RegExp(`\\b${escapeRegex(needle)}\\b`, "i").test(haystack);
  }
  return haystack.includes(needle);
}

function normalizeText(value: string): string {
  return value.replace(/^\s*\d+:\s*/gm, "").replace(/\s+/g, " ").trim().toLowerCase();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function addLower(values: Set<string>, value: string | undefined): void {
  if (value?.trim()) {
    values.add(value.trim().toLowerCase());
  }
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 180);
}
