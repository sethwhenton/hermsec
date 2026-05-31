import path from "node:path";
import { toPosixPath } from "../shared/paths.js";
import { clampText, redactSecrets, stableId } from "../shared/text.js";
import type { Finding, FindingCategory, Severity } from "../shared/types.js";
import type { ScannerCommandId } from "./process.js";

export type ParserContext = {
  repoRoot: string;
  sourcePath?: string;
};

export type ParseResult = {
  findings: Finding[];
  errors: string[];
};

type ExternalCandidate = Omit<Finding, "id" | "fingerprint">;

export function parseScannerJson(scanner: ScannerCommandId, content: string, context: ParserContext): ParseResult {
  if (!content.trim()) {
    return { findings: [], errors: [] };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    return {
      findings: [],
      errors: [`${scanner} returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`],
    };
  }

  const candidates = parseScannerValue(scanner, parsed, context);
  return {
    findings: candidates.map(finalizeExternalFinding),
    errors: [],
  };
}

function parseScannerValue(scanner: ScannerCommandId, value: unknown, context: ParserContext): ExternalCandidate[] {
  switch (scanner) {
    case "semgrep":
      return parseSemgrep(value, context);
    case "gitleaks":
      return parseGitleaks(value, context);
    case "bandit":
      return parseBandit(value, context);
    case "pip-audit":
      return parsePipAudit(value, context);
    case "osv-scanner":
      return parseOsvScanner(value, context);
    case "pmg":
      return parseNpmAudit(value, context);
  }
}

function parseSemgrep(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const results = Array.isArray(root?.results) ? root.results : [];
  return results.flatMap((raw): ExternalCandidate[] => {
    const result = asRecord(raw);
    const extra = asRecord(result?.extra);
    if (!result || !extra) {
      return [];
    }
    const metadata = asRecord(extra.metadata);
    const message = stringValue(extra.message) ?? stringValue(result.check_id) ?? "Semgrep finding";
    const file = normalizeFindingPath(stringValue(result.path), context);
    const start = asRecord(result.start);
    const end = asRecord(result.end);
    const line = numberValue(start?.line);
    const identifiers = identifiersFromUnknown(metadata);
    const cwe = cwesFromUnknown(metadata?.cwe);
    const ruleId = stringValue(result.check_id) ?? "semgrep";
    return [{
      tool: "semgrep",
      title: message,
      category: categoryFromSemgrep(metadata),
      severity: semgrepSeverity(stringValue(extra.severity) ?? stringValue(metadata?.severity)),
      confidence: "high",
      description: "Semgrep reported a static analysis finding from Hermsec's local ruleset or project scanner configuration.",
      evidence: evidenceWithLocation(file, line, message),
      remediation: remediationFromMetadata(metadata) ?? "Review the matched code path and apply the Semgrep rule guidance.",
      ruleId,
      ...(cwe.length > 0 ? { cwe } : {}),
      ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
      ...(file ? { location: locationFor(file, line, numberValue(end?.line)) } : {}),
    }];
  });
}

function parseGitleaks(value: unknown, context: ParserContext): ExternalCandidate[] {
  const leaks = Array.isArray(value) ? value : Array.isArray(asRecord(value)?.findings) ? asRecord(value)?.findings as unknown[] : [];
  return leaks.flatMap((raw): ExternalCandidate[] => {
    const leak = asRecord(raw);
    if (!leak) {
      return [];
    }
    const ruleId = stringValue(leak.RuleID) ?? stringValue(leak.ruleID) ?? stringValue(leak.rule_id) ?? "gitleaks";
    const description = stringValue(leak.Description) ?? stringValue(leak.description) ?? "Gitleaks secret finding";
    const file = normalizeFindingPath(stringValue(leak.File) ?? stringValue(leak.file), context);
    const startLine = numberValue(leak.StartLine) ?? numberValue(leak.startLine) ?? numberValue(leak.line);
    const endLine = numberValue(leak.EndLine) ?? numberValue(leak.endLine);
    const secret = stringValue(leak.Secret) ?? stringValue(leak.secret);
    const match = stringValue(leak.Match) ?? stringValue(leak.match);
    const evidence = redactExact(
      evidenceWithLocation(file, startLine, `${description}${match ? `: ${match}` : ""}`),
      [secret, match],
    );
    return [{
      tool: "gitleaks",
      title: description,
      category: "secret",
      severity: "high",
      confidence: "confirmed",
      description: "Gitleaks reported secret-like material in the scanned working tree.",
      evidence,
      remediation: "Remove the secret, rotate any exposed credential, and keep real secrets outside the repository.",
      ruleId,
      cwe: ["CWE-798"],
      ...(file ? { location: locationFor(file, startLine, endLine) } : {}),
    }];
  });
}

function parseBandit(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const results = Array.isArray(root?.results) ? root.results : [];
  return results.flatMap((raw): ExternalCandidate[] => {
    const result = asRecord(raw);
    if (!result) {
      return [];
    }
    const text = stringValue(result.issue_text) ?? stringValue(result.test_name) ?? "Bandit finding";
    const file = normalizeFindingPath(stringValue(result.filename), context);
    const line = numberValue(result.line_number);
    const lineRange = Array.isArray(result.line_range) ? result.line_range.map(numberValue).filter((item): item is number => item !== undefined) : [];
    const issueCwe = asRecord(result.issue_cwe);
    const cwe = cwesFromUnknown(issueCwe?.id ?? issueCwe?.link);
    const ruleId = stringValue(result.test_id) ?? stringValue(result.test_name) ?? "bandit";
    const confidence = banditConfidence(stringValue(result.issue_confidence));
    return [{
      tool: "bandit",
      title: text,
      category: "code",
      severity: banditSeverity(stringValue(result.issue_severity)),
      confidence,
      description: "Bandit reported a Python static analysis finding.",
      evidence: evidenceWithLocation(file, line, text),
      remediation: "Review the affected Python code and apply Bandit's recommended defensive pattern.",
      ruleId,
      ...(cwe.length > 0 ? { cwe } : {}),
      ...(file ? { location: locationFor(file, line, lineRange[lineRange.length - 1]) } : {}),
    }];
  });
}

function parsePipAudit(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const dependencies = Array.isArray(root?.dependencies) ? root.dependencies : [];
  return dependencies.flatMap((raw): ExternalCandidate[] => {
    const dependency = asRecord(raw);
    if (!dependency) {
      return [];
    }
    const packageName = stringValue(dependency.name) ?? "unknown";
    const version = stringValue(dependency.version);
    const vulns = Array.isArray(dependency.vulns) ? dependency.vulns : [];
    return vulns.flatMap((rawVuln): ExternalCandidate[] => {
      const vuln = asRecord(rawVuln);
      if (!vuln) {
        return [];
      }
      const id = stringValue(vuln.id) ?? "unknown";
      const aliases = stringArray(vuln.aliases);
      const identifiers = identifiersFromValues([id, ...aliases]);
      const title = stringValue(vuln.description) ?? `pip-audit vulnerability ${id}`;
      const fixVersions = stringArray(vuln.fix_versions);
      return [{
        tool: "pip-audit",
        title: clampText(title, 140),
        category: "dependency",
        severity: "medium",
        confidence: "high",
        description: "pip-audit reported a known vulnerability for a pinned Python dependency.",
        evidence: `${packageName}${version ? `@${version}` : ""} is affected by ${[id, ...aliases].filter(Boolean).join(", ")}.`,
        remediation: fixVersions.length > 0
          ? `Upgrade ${packageName} to one of the fixed versions: ${fixVersions.join(", ")}.`
          : `Review the advisory for ${packageName} and upgrade to a non-vulnerable version when available.`,
        ruleId: `pip-audit:${id}`,
        ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
        package: packageInfo("pypi", packageName, version),
        ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
      }];
    });
  });
}

function parseOsvScanner(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const results = Array.isArray(root?.results) ? root.results : [];
  return results.flatMap((rawResult): ExternalCandidate[] => {
    const result = asRecord(rawResult);
    if (!result) {
      return [];
    }
    const source = asRecord(result.source);
    const sourcePath = normalizeFindingPath(stringValue(source?.path) ?? context.sourcePath, context);
    const packages = Array.isArray(result.packages) ? result.packages : [];
    return packages.flatMap((rawPackage): ExternalCandidate[] => {
      const packageRecord = asRecord(rawPackage);
      const pkg = asRecord(packageRecord?.package);
      if (!packageRecord || !pkg) {
        return [];
      }
      const packageName = stringValue(pkg.name) ?? "unknown";
      const version = stringValue(pkg.version);
      const ecosystem = normalizeEcosystem(stringValue(pkg.ecosystem));
      const vulns = Array.isArray(packageRecord.vulnerabilities) ? packageRecord.vulnerabilities : [];
      return vulns.flatMap((rawVuln): ExternalCandidate[] => {
        const vuln = asRecord(rawVuln);
        if (!vuln) {
          return [];
        }
        const id = stringValue(vuln.id) ?? "unknown";
        const aliases = stringArray(vuln.aliases);
        const identifiers = identifiersFromValues([id, ...aliases]);
        const summary = stringValue(vuln.summary) ?? stringValue(vuln.details) ?? `OSV vulnerability ${id}`;
        return [{
          tool: "osv-scanner",
          title: clampText(summary, 140),
          category: "dependency",
          severity: osvSeverity(vuln),
          confidence: "high",
          description: "OSV-Scanner reported a known vulnerability for a dependency in a recognized manifest or lockfile.",
          evidence: `${packageName}${version ? `@${version}` : ""} is affected by ${[id, ...aliases].filter(Boolean).join(", ")}.`,
          remediation: remediationFromAffected(packageName, vuln) ?? `Review the OSV advisory for ${packageName} and upgrade to a non-vulnerable version when available.`,
          ruleId: `osv:${id}`,
          ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
          package: packageInfo(ecosystem, packageName, version),
          ...(sourcePath ? { location: { file: sourcePath } } : {}),
        }];
      });
    });
  });
}

function parseNpmAudit(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  if (!root) {
    return [];
  }
  const modern = parseModernNpmAudit(root, context);
  const legacy = parseLegacyNpmAudit(root, context);
  return [...modern, ...legacy];
}

function parseModernNpmAudit(root: Record<string, unknown>, context: ParserContext): ExternalCandidate[] {
  const vulnerabilities = asRecord(root.vulnerabilities);
  if (!vulnerabilities) {
    return [];
  }

  const findings: ExternalCandidate[] = [];
  for (const [packageName, rawVulnerability] of Object.entries(vulnerabilities)) {
    const vulnerability = asRecord(rawVulnerability);
    if (!vulnerability) {
      continue;
    }
    const via = Array.isArray(vulnerability.via) ? vulnerability.via : [];
    const advisoryObjects = via.map(asRecord).filter((item): item is Record<string, unknown> => item !== undefined);
    if (advisoryObjects.length === 0) {
      findings.push(npmAuditFinding(packageName, vulnerability, undefined, context));
      continue;
    }
    for (const advisory of advisoryObjects) {
      findings.push(npmAuditFinding(packageName, vulnerability, advisory, context));
    }
  }
  return findings;
}

function parseLegacyNpmAudit(root: Record<string, unknown>, context: ParserContext): ExternalCandidate[] {
  const advisories = asRecord(root.advisories);
  if (!advisories) {
    return [];
  }
  const findings: ExternalCandidate[] = [];
  for (const advisory of Object.values(advisories).map(asRecord).filter((item): item is Record<string, unknown> => item !== undefined)) {
    const packageName = stringValue(advisory.module_name) ?? stringValue(advisory.name) ?? "unknown";
    const identifiers = identifiersFromUnknown(advisory);
    findings.push({
      tool: "pmg",
      title: stringValue(advisory.title) ?? `npm audit vulnerability in ${packageName}`,
      category: "dependency",
      severity: npmSeverity(stringValue(advisory.severity)),
      confidence: "high",
      description: "PMG wrapped npm audit reported a known npm dependency vulnerability without installing packages.",
      evidence: `${packageName} ${stringValue(advisory.vulnerable_versions) ?? ""} ${stringValue(advisory.url) ?? ""}`.trim(),
      remediation: stringValue(advisory.recommendation) ?? `Upgrade ${packageName} to a non-vulnerable version after dependency review.`,
      ruleId: `npm-audit:${stringValue(advisory.id) ?? stringValue(advisory.url) ?? packageName}`,
      ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
      package: packageInfo("npm", packageName, undefined),
      ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
    });
  }
  return findings;
}

function npmAuditFinding(
  packageName: string,
  vulnerability: Record<string, unknown>,
  advisory: Record<string, unknown> | undefined,
  context: ParserContext,
): ExternalCandidate {
  const advisoryText = advisory ? JSON.stringify(advisory) : JSON.stringify(vulnerability);
  const identifiers = identifiersFromValues([advisoryText]);
  const title = stringValue(advisory?.title) ?? `${packageName} vulnerability`;
  const severity = npmSeverity(stringValue(advisory?.severity) ?? stringValue(vulnerability.severity));
  return {
    tool: "pmg",
    title,
    category: "dependency",
    severity,
    confidence: "high",
    description: "PMG wrapped npm audit reported a known npm dependency vulnerability without installing packages.",
    evidence: `${packageName} ${stringValue(advisory?.range) ?? stringValue(vulnerability.range) ?? ""} ${stringValue(advisory?.url) ?? ""}`.trim(),
    remediation: npmRemediation(packageName, vulnerability),
    ruleId: `npm-audit:${stringValue(advisory?.source) ?? stringValue(advisory?.url) ?? packageName}`,
    ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
    package: packageInfo("npm", packageName, undefined),
    ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
  };
}

function finalizeExternalFinding(candidate: ExternalCandidate): Finding {
  const fingerprintSource = JSON.stringify({
    tool: candidate.tool,
    ruleId: candidate.ruleId,
    category: candidate.category,
    file: candidate.location?.file,
    line: candidate.location?.startLine,
    package: candidate.package,
    title: candidate.title,
    identifiers: candidate.identifiers,
  });
  const fingerprint = stableId(fingerprintSource, "fp");
  return {
    ...candidate,
    evidence: redactSensitiveEvidence(clampText(candidate.evidence, 700)),
    id: stableId(fingerprintSource, "finding"),
    fingerprint,
  };
}

function categoryFromSemgrep(metadata: Record<string, unknown> | undefined): FindingCategory {
  const category = stringValue(metadata?.category)?.toLowerCase();
  if (category === "security" || category === "correctness") {
    return "code";
  }
  return "code";
}

function semgrepSeverity(value: string | undefined): Severity {
  switch (value?.toUpperCase()) {
    case "ERROR":
    case "HIGH":
      return "high";
    case "WARNING":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    case "INFO":
      return "info";
    default:
      return "medium";
  }
}

function banditSeverity(value: string | undefined): Severity {
  switch (value?.toUpperCase()) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function banditConfidence(value: string | undefined): Finding["confidence"] {
  switch (value?.toUpperCase()) {
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    case "MEDIUM":
    default:
      return "medium";
  }
}

function npmSeverity(value: string | undefined): Severity {
  switch (value?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "medium";
  }
}

function osvSeverity(vuln: Record<string, unknown>): Severity {
  const databaseSpecific = asRecord(vuln.database_specific);
  const severity = npmSeverity(stringValue(databaseSpecific?.severity));
  if (severity !== "medium" || stringValue(databaseSpecific?.severity)) {
    return severity;
  }
  return "medium";
}

function remediationFromMetadata(metadata: Record<string, unknown> | undefined): string | undefined {
  return stringValue(metadata?.fix) ?? stringValue(metadata?.remediation);
}

function remediationFromAffected(packageName: string, vuln: Record<string, unknown>): string | undefined {
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  const fixed = new Set<string>();
  for (const rawAffected of affected) {
    const affectedRecord = asRecord(rawAffected);
    const ranges = Array.isArray(affectedRecord?.ranges) ? affectedRecord.ranges : [];
    for (const rawRange of ranges) {
      const range = asRecord(rawRange);
      const events = Array.isArray(range?.events) ? range.events : [];
      for (const event of events.map(asRecord)) {
        const fixedVersion = stringValue(event?.fixed);
        if (fixedVersion) {
          fixed.add(fixedVersion);
        }
      }
    }
  }
  return fixed.size > 0 ? `Upgrade ${packageName} to a fixed version: ${[...fixed].join(", ")}.` : undefined;
}

function npmRemediation(packageName: string, vulnerability: Record<string, unknown>): string {
  const fixAvailable = vulnerability.fixAvailable;
  if (fixAvailable === false) {
    return `No automatic npm audit fix is available for ${packageName}; review upstream guidance and upgrade manually.`;
  }
  if (fixAvailable === true) {
    return `A fix is available for ${packageName}; upgrade after dependency review.`;
  }
  const fix = asRecord(fixAvailable);
  const version = stringValue(fix?.version);
  return version
    ? `Upgrade ${packageName} to ${version} after dependency review.`
    : `Review the npm advisory for ${packageName} and upgrade to a non-vulnerable version.`;
}

function packageInfo(ecosystem: string, name: string, version: string | undefined): NonNullable<Finding["package"]> {
  const info: NonNullable<Finding["package"]> = { ecosystem, name };
  if (version) {
    info.installedVersion = version;
  }
  return info;
}

function identifiersFromUnknown(value: unknown): NonNullable<Finding["identifiers"]> {
  return identifiersFromValues(flattenStrings(value));
}

function identifiersFromValues(values: readonly string[]): NonNullable<Finding["identifiers"]> {
  const text = values.join("\n");
  return {
    cve: uniqueMatches(text, /\bCVE-\d{4}-\d{4,}\b/gi).map((item) => item.toUpperCase()),
    ghsa: uniqueMatches(text, /\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/gi).map((item) => item.toUpperCase()),
    osv: uniqueMatches(text, /\b(?:OSV|PYSEC|RUSTSEC|GO)-\d{4}-\d+\b/gi).map((item) => item.toUpperCase()),
  };
}

function hasIdentifiers(identifiers: NonNullable<Finding["identifiers"]>): boolean {
  return (identifiers.cve?.length ?? 0) > 0 || (identifiers.ghsa?.length ?? 0) > 0 || (identifiers.osv?.length ?? 0) > 0;
}

function cwesFromUnknown(value: unknown): string[] {
  return uniqueMatches(flattenStrings(value).join("\n"), /\bCWE-?\d+\b/gi).map((item) => {
    const number = item.replace(/\D/g, "");
    return `CWE-${number}`;
  });
}

function flattenStrings(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    return value.flatMap(flattenStrings);
  }
  const record = asRecord(value);
  if (record) {
    return Object.values(record).flatMap(flattenStrings);
  }
  return [];
}

function uniqueMatches(value: string, pattern: RegExp): string[] {
  return [...new Set([...value.matchAll(pattern)].map((match) => match[0]))];
}

function normalizeFindingPath(value: string | undefined, context: ParserContext): string {
  if (!value) {
    return "";
  }
  const normalizedRoot = path.resolve(context.repoRoot);
  const normalizedValue = path.isAbsolute(value) ? path.resolve(value) : path.resolve(context.repoRoot, value);
  const relative = path.relative(normalizedRoot, normalizedValue);
  if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
    return toPosixPath(relative);
  }
  return toPosixPath(value).replace(/^\.\//, "");
}

function normalizeEcosystem(value: string | undefined): string {
  switch (value?.toLowerCase()) {
    case "pypi":
    case "python":
      return "pypi";
    case "npm":
    case "javascript":
      return "npm";
    default:
      return value?.toLowerCase() ?? "unknown";
  }
}

function evidenceWithLocation(file: string, line: number | undefined, message: string): string {
  const location = file ? `${file}${line !== undefined ? `:${line}` : ""}` : "scanner output";
  return `${location} ${message}`.trim();
}

function locationFor(file: string, startLine: number | undefined, endLine: number | undefined): NonNullable<Finding["location"]> {
  const location: NonNullable<Finding["location"]> = { file };
  if (startLine !== undefined) {
    location.startLine = startLine;
  }
  if (endLine !== undefined && endLine !== startLine) {
    location.endLine = endLine;
  }
  return location;
}

function redactExact(value: string, secrets: ReadonlyArray<string | undefined>): string {
  let redacted = value;
  for (const secret of secrets) {
    if (secret) {
      redacted = redacted.split(secret).join("[REDACTED_SECRET]");
    }
  }
  return redactSensitiveEvidence(redacted);
}

function redactSensitiveEvidence(value: string): string {
  return redactSecrets(value)
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_KEY]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g, "gh_[REDACTED]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "xox-[REDACTED]");
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
