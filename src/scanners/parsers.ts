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
    const textCandidates = parseScannerText(scanner, content, context);
    if (textCandidates.length > 0) {
      return {
        findings: textCandidates.map(finalizeExternalFinding),
        errors: [],
      };
    }
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
    case "trufflehog":
      return parseTruffleHog(value, context);
    case "trivy":
      return parseTrivy(value, context);
    case "checkov":
      return parseCheckov(value, context);
    case "bandit":
      return parseBandit(value, context);
    case "pip-audit":
      return parsePipAudit(value, context);
    case "osv-scanner":
      return parseOsvScanner(value, context);
    case "pmg":
      return parseNpmAudit(value, context);
    case "retire":
      return parseRetire(value, context);
    case "spotbugs":
      return parseSpotBugs(value, context);
    case "dependency-check":
      return parseDependencyCheck(value, context);
    case "psalm":
      return parsePsalm(value, context);
    case "composer":
      return parseComposerAudit(value, context);
    case "gosec":
      return parseGosec(value, context);
    case "govulncheck":
      return parseGovulncheck(value, context);
    case "cargo":
      return parseCargoAudit(value, context);
    case "brakeman":
      return parseBrakeman(value, context);
    case "flawfinder":
      return parseSarif("flawfinder", value, context);
    case "cppcheck":
      return [];
    case "dotnet":
      return parseDotnetVulnerable(value, context);
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

function parseTruffleHog(value: unknown, context: ParserContext): ExternalCandidate[] {
  const records = Array.isArray(value) ? value : [value];
  return records.flatMap((raw): ExternalCandidate[] => {
    const item = asRecord(raw);
    if (!item) return [];
    const source = asRecord(item.SourceMetadata);
    const data = asRecord(source?.Data);
    const filesystem = asRecord(data?.Filesystem);
    const git = asRecord(data?.Git);
    const detector = stringValue(item.DetectorName) ?? stringValue(item.detector_name) ?? "secret";
    const file = normalizeFindingPath(
      stringValue(filesystem?.file) ?? stringValue(filesystem?.File) ?? stringValue(git?.file) ?? stringValue(git?.File),
      context,
    );
    const line = numberValue(filesystem?.line) ?? numberValue(filesystem?.Line) ?? numberValue(git?.line);
    const verified = Boolean(item.Verified ?? item.verified);
    return [{
      tool: "trufflehog",
      title: `${detector} secret${verified ? " (verified)" : ""}`,
      category: "secret",
      severity: verified ? "critical" : "high",
      confidence: verified ? "confirmed" : "medium",
      description: "TruffleHog reported secret-like material in the scanned project.",
      evidence: evidenceWithLocation(file, line, `${detector} secret evidence was redacted.`),
      remediation: "Remove the secret, rotate the credential if real, and keep sensitive values outside the repository.",
      ruleId: `trufflehog:${detector}`,
      cwe: ["CWE-798"],
      ...(file ? { location: locationFor(file, line, undefined) } : {}),
    }];
  });
}

function parseTrivy(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const results = Array.isArray(root?.Results) ? root.Results : [];
  const findings: ExternalCandidate[] = [];
  for (const rawResult of results) {
    const result = asRecord(rawResult);
    if (!result) continue;
    const target = normalizeFindingPath(stringValue(result.Target), context);
    const vulnerabilities = Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : [];
    for (const rawVuln of vulnerabilities.map(asRecord)) {
      if (!rawVuln) continue;
      const packageName = stringValue(rawVuln.PkgName) ?? "unknown";
      const id = stringValue(rawVuln.VulnerabilityID) ?? "unknown";
      const installed = stringValue(rawVuln.InstalledVersion);
      const fixed = stringValue(rawVuln.FixedVersion);
      const identifiers = identifiersFromValues([id, ...stringArray(rawVuln.References)]);
      findings.push({
        tool: "trivy",
        title: stringValue(rawVuln.Title) ?? `${packageName} vulnerability ${id}`,
        category: "dependency",
        severity: npmSeverity(stringValue(rawVuln.Severity)),
        confidence: "high",
        description: "Trivy reported a known vulnerable dependency or package.",
        evidence: `${packageName}${installed ? `@${installed}` : ""} is affected by ${id}.`,
        remediation: fixed ? `Upgrade ${packageName} to a fixed version: ${fixed}.` : `Review the Trivy advisory for ${packageName}.`,
        ruleId: `trivy:${id}`,
        ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
        package: packageInfo(normalizeEcosystem(stringValue(rawVuln.PkgType)), packageName, installed),
        ...(target ? { location: { file: target } } : {}),
      });
    }
    const secrets = Array.isArray(result.Secrets) ? result.Secrets : [];
    for (const rawSecret of secrets.map(asRecord)) {
      if (!rawSecret) continue;
      const ruleId = stringValue(rawSecret.RuleID) ?? "trivy-secret";
      const line = numberValue(rawSecret.StartLine);
      findings.push({
        tool: "trivy",
        title: stringValue(rawSecret.Title) ?? "Trivy secret finding",
        category: "secret",
        severity: npmSeverity(stringValue(rawSecret.Severity)) === "medium" ? "high" : npmSeverity(stringValue(rawSecret.Severity)),
        confidence: "medium",
        description: "Trivy reported secret-like material.",
        evidence: evidenceWithLocation(target, line, "Secret evidence was redacted."),
        remediation: "Remove and rotate the secret if real.",
        ruleId,
        cwe: ["CWE-798"],
        ...(target ? { location: locationFor(target, line, undefined) } : {}),
      });
    }
    const misconfigurations = Array.isArray(result.Misconfigurations) ? result.Misconfigurations : [];
    for (const rawMisconfig of misconfigurations.map(asRecord)) {
      if (!rawMisconfig) continue;
      const id = stringValue(rawMisconfig.ID) ?? "trivy-misconfig";
      findings.push({
        tool: "trivy",
        title: stringValue(rawMisconfig.Title) ?? id,
        category: "config",
        severity: npmSeverity(stringValue(rawMisconfig.Severity)),
        confidence: "high",
        description: stringValue(rawMisconfig.Description) ?? "Trivy reported an IaC or configuration misconfiguration.",
        evidence: evidenceWithLocation(target, undefined, stringValue(rawMisconfig.Message) ?? id),
        remediation: stringValue(rawMisconfig.Resolution) ?? "Review and harden the affected configuration.",
        ruleId: id,
        ...(target ? { location: { file: target } } : {}),
      });
    }
  }
  return findings;
}

function parseCheckov(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const failed = [
    ...(Array.isArray(root?.failed_checks) ? root.failed_checks : []),
    ...Object.values(asRecord(root?.results) ?? {}).flatMap((item) => Array.isArray(item) ? item : Array.isArray(asRecord(item)?.failed_checks) ? asRecord(item)?.failed_checks as unknown[] : []),
  ];
  return failed.flatMap((raw): ExternalCandidate[] => {
    const check = asRecord(raw);
    if (!check) return [];
    const file = normalizeFindingPath(stringValue(check.file_path) ?? stringValue(check.file_abs_path), context);
    const range = Array.isArray(check.file_line_range) ? check.file_line_range.map(numberValue).filter((item): item is number => item !== undefined) : [];
    const id = stringValue(check.check_id) ?? "checkov";
    return [{
      tool: "checkov",
      title: stringValue(check.check_name) ?? id,
      category: "config",
      severity: "medium",
      confidence: "high",
      description: "Checkov reported an infrastructure-as-code or workflow misconfiguration.",
      evidence: evidenceWithLocation(file, range[0], stringValue(check.guideline) ?? id),
      remediation: stringValue(check.guideline) ?? "Review Checkov guidance and update the affected configuration.",
      ruleId: id,
      ...(file ? { location: locationFor(file, range[0], range[1]) } : {}),
    }];
  });
}

function parseRetire(value: unknown, context: ParserContext): ExternalCandidate[] {
  const items = Array.isArray(value) ? value : Array.isArray(asRecord(value)?.data) ? asRecord(value)?.data as unknown[] : [];
  return items.flatMap((raw): ExternalCandidate[] => {
    const item = asRecord(raw);
    if (!item) return [];
    const file = normalizeFindingPath(stringValue(item.file) ?? stringValue(item.filepath), context);
    const results = Array.isArray(item.results) ? item.results : [];
    return results.flatMap((rawResult): ExternalCandidate[] => {
      const result = asRecord(rawResult);
      if (!result) return [];
      const component = stringValue(result.component) ?? stringValue(result.name) ?? "javascript-library";
      const version = stringValue(result.version);
      const vulns = Array.isArray(result.vulnerabilities) ? result.vulnerabilities : [];
      return vulns.map((rawVuln): ExternalCandidate => {
        const vuln = asRecord(rawVuln) ?? {};
        const identifiers = identifiersFromUnknown(vuln);
        return {
          tool: "retire",
          title: stringValue(vuln.summary) ?? `${component} has a known vulnerability`,
          category: "dependency",
          severity: npmSeverity(stringValue(vuln.severity)),
          confidence: "high",
          description: "Retire.js reported a known vulnerable JavaScript library.",
          evidence: evidenceWithLocation(file, undefined, `${component}${version ? `@${version}` : ""}`),
          remediation: stringValue(vuln.info) ?? `Upgrade or remove ${component}.`,
          ruleId: `retire:${component}:${version ?? "unknown"}`,
          ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
          package: packageInfo("npm", component, version),
          ...(file ? { location: { file } } : {}),
        };
      });
    });
  });
}

function parseSpotBugs(value: unknown, context: ParserContext): ExternalCandidate[] {
  return parseSarif("spotbugs", value, context);
}

function parseDependencyCheck(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const dependencies = Array.isArray(root?.dependencies) ? root.dependencies : [];
  return dependencies.flatMap((raw): ExternalCandidate[] => {
    const dep = asRecord(raw);
    if (!dep) return [];
    const file = normalizeFindingPath(stringValue(dep.filePath) ?? stringValue(dep.fileName), context);
    const packageName = stringValue(dep.fileName) ?? stringValue(dep.packageName) ?? "dependency";
    const vulns = Array.isArray(dep.vulnerabilities) ? dep.vulnerabilities : [];
    return vulns.flatMap((rawVuln): ExternalCandidate[] => {
      const vuln = asRecord(rawVuln);
      if (!vuln) return [];
      const id = stringValue(vuln.name) ?? "dependency-check";
      const identifiers = identifiersFromUnknown(vuln);
      return [{
        tool: "dependency-check",
        title: stringValue(vuln.title) ?? `${packageName} vulnerability ${id}`,
        category: "dependency",
        severity: npmSeverity(stringValue(vuln.severity)),
        confidence: "medium",
        description: "OWASP Dependency-Check reported a vulnerable component.",
        evidence: evidenceWithLocation(file, undefined, `${packageName} is affected by ${id}.`),
        remediation: "Review the advisory evidence and upgrade or replace the affected component.",
        ruleId: `dependency-check:${id}`,
        ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
        package: packageInfo("unknown", packageName, undefined),
        ...(file ? { location: { file } } : {}),
      }];
    });
  });
}

function parsePsalm(value: unknown, context: ParserContext): ExternalCandidate[] {
  const issues = Array.isArray(value) ? value : Array.isArray(asRecord(value)?.issues) ? asRecord(value)?.issues as unknown[] : [];
  return issues.flatMap((raw): ExternalCandidate[] => {
    const issue = asRecord(raw);
    if (!issue) return [];
    const file = normalizeFindingPath(stringValue(issue.file_path) ?? stringValue(issue.file_name), context);
    const line = numberValue(issue.line_from) ?? numberValue(issue.line);
    const type = stringValue(issue.type) ?? "psalm";
    return [{
      tool: "psalm",
      title: stringValue(issue.message) ?? type,
      category: "code",
      severity: "high",
      confidence: "medium",
      description: "Psalm taint analysis reported a PHP data-flow issue.",
      evidence: evidenceWithLocation(file, line, stringValue(issue.message) ?? type),
      remediation: "Trace the tainted source to the sink and sanitize, validate, or parameterize the data flow.",
      ruleId: `psalm:${type}`,
      ...(file ? { location: locationFor(file, line, numberValue(issue.line_to)) } : {}),
    }];
  });
}

function parseComposerAudit(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const advisories = asRecord(root?.advisories) ?? {};
  return Object.entries(advisories).flatMap(([packageName, rawList]): ExternalCandidate[] => {
    const list = Array.isArray(rawList) ? rawList : Object.values(asRecord(rawList) ?? {});
    return list.flatMap((raw): ExternalCandidate[] => {
      const advisory = asRecord(raw);
      if (!advisory) return [];
      const id = stringValue(advisory.advisoryId) ?? stringValue(advisory.cve) ?? stringValue(advisory.link) ?? packageName;
      const identifiers = identifiersFromUnknown(advisory);
      return [{
        tool: "composer",
        title: stringValue(advisory.title) ?? `${packageName} vulnerability`,
        category: "dependency",
        severity: npmSeverity(stringValue(advisory.severity)),
        confidence: "high",
        description: "Composer audit reported a known vulnerable PHP dependency.",
        evidence: `${packageName} is affected by ${id}.`,
        remediation: `Upgrade ${packageName} to a non-vulnerable version after dependency review.`,
        ruleId: `composer-audit:${id}`,
        ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
        package: packageInfo("packagist", packageName, undefined),
        ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
      }];
    });
  });
}

function parseGosec(value: unknown, context: ParserContext): ExternalCandidate[] {
  const issues = Array.isArray(asRecord(value)?.Issues) ? asRecord(value)?.Issues as unknown[] : [];
  return issues.flatMap((raw): ExternalCandidate[] => {
    const issue = asRecord(raw);
    if (!issue) return [];
    const file = normalizeFindingPath(stringValue(issue.file), context);
    const line = numberValue(issue.line);
    const ruleId = stringValue(issue.rule_id) ?? "gosec";
    return [{
      tool: "gosec",
      title: stringValue(issue.details) ?? ruleId,
      category: "code",
      severity: npmSeverity(stringValue(issue.severity)),
      confidence: gosecConfidence(stringValue(issue.confidence)),
      description: "gosec reported a Go source security issue.",
      evidence: evidenceWithLocation(file, line, stringValue(issue.details) ?? ruleId),
      remediation: "Review the affected Go code and apply the gosec rule guidance.",
      ruleId,
      cwe: cwesFromUnknown(issue.cwe),
      ...(file ? { location: locationFor(file, line, undefined) } : {}),
    }];
  });
}

function parseGovulncheck(value: unknown, context: ParserContext): ExternalCandidate[] {
  const records = Array.isArray(value) ? value : [value];
  return records.flatMap((raw): ExternalCandidate[] => {
    const item = asRecord(raw);
    const finding = asRecord(item?.finding) ?? asRecord(item?.Finding);
    const osv = asRecord(item?.osv) ?? asRecord(finding?.osv);
    if (!finding && !osv) return [];
    const id = stringValue(osv?.id) ?? stringValue(finding?.osv) ?? "govulncheck";
    const identifiers = identifiersFromValues([id, ...stringArray(osv?.aliases)]);
    const trace = Array.isArray(finding?.trace) ? finding.trace.map(asRecord).filter((entry): entry is Record<string, unknown> => Boolean(entry)) : [];
    const first = trace[0];
    const file = normalizeFindingPath(stringValue(first?.file), context);
    const line = numberValue(first?.line);
    return [{
      tool: "govulncheck",
      title: stringValue(osv?.summary) ?? `Go vulnerability ${id}`,
      category: "dependency",
      severity: "high",
      confidence: trace.length > 0 ? "high" : "medium",
      description: "govulncheck reported a reachable Go vulnerability or vulnerable dependency.",
      evidence: evidenceWithLocation(file, line, id),
      remediation: "Upgrade the affected Go module or stop calling the vulnerable symbol.",
      ruleId: `govulncheck:${id}`,
      ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
      ...(file ? { location: locationFor(file, line, undefined) } : {}),
    }];
  });
}

function parseCargoAudit(value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const vulnerabilityRoot = asRecord(root?.vulnerabilities);
  const vulnerabilities = Array.isArray(vulnerabilityRoot?.list)
    ? vulnerabilityRoot.list
    : Array.isArray(root?.vulnerabilities)
      ? root.vulnerabilities
      : [];
  return vulnerabilities.flatMap((raw): ExternalCandidate[] => {
    const item = asRecord(raw);
    const advisory = asRecord(item?.advisory) ?? item;
    const versions = asRecord(item?.versions);
    const pkg = asRecord(item?.package);
    if (!advisory) return [];
    const id = stringValue(advisory.id) ?? "rustsec";
    const packageName = stringValue(pkg?.name) ?? stringValue(advisory.package) ?? "crate";
    const identifiers = identifiersFromValues([id, ...stringArray(advisory.aliases)]);
    return [{
      tool: "cargo",
      title: stringValue(advisory.title) ?? `${packageName} advisory ${id}`,
      category: "dependency",
      severity: "high",
      confidence: "high",
      description: "cargo-audit reported a RustSec advisory for a Rust dependency.",
      evidence: `${packageName} is affected by ${id}.`,
      remediation: stringValue(versions?.patched) ? `Upgrade ${packageName} to ${String(versions?.patched)}.` : `Review the RustSec advisory for ${packageName}.`,
      ruleId: `cargo-audit:${id}`,
      ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
      package: packageInfo("crates.io", packageName, undefined),
      ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
    }];
  });
}

function parseBrakeman(value: unknown, context: ParserContext): ExternalCandidate[] {
  const warnings = Array.isArray(asRecord(value)?.warnings) ? asRecord(value)?.warnings as unknown[] : [];
  return warnings.flatMap((raw): ExternalCandidate[] => {
    const warning = asRecord(raw);
    if (!warning) return [];
    const file = normalizeFindingPath(stringValue(warning.file), context);
    const line = numberValue(warning.line);
    const type = stringValue(warning.warning_type) ?? "brakeman";
    return [{
      tool: "brakeman",
      title: stringValue(warning.message) ?? type,
      category: "code",
      severity: brakemanSeverity(numberValue(warning.confidence)),
      confidence: brakemanConfidence(numberValue(warning.confidence)),
      description: "Brakeman reported a Rails security issue.",
      evidence: evidenceWithLocation(file, line, stringValue(warning.message) ?? type),
      remediation: "Review the affected Rails code and apply the Brakeman warning guidance.",
      ruleId: `brakeman:${type}`,
      cwe: cwesFromUnknown(warning.cwe_id),
      ...(file ? { location: locationFor(file, line, undefined) } : {}),
    }];
  });
}

function parseDotnetVulnerable(value: unknown, context: ParserContext): ExternalCandidate[] {
  const projects = Array.isArray(asRecord(value)?.projects) ? asRecord(value)?.projects as unknown[] : [];
  return projects.flatMap((rawProject): ExternalCandidate[] => {
    const project = asRecord(rawProject);
    if (!project) return [];
    const frameworks = Array.isArray(project.frameworks) ? project.frameworks : [];
    return frameworks.flatMap((rawFramework): ExternalCandidate[] => {
      const framework = asRecord(rawFramework);
      const packages = [
        ...(Array.isArray(framework?.topLevelPackages) ? framework.topLevelPackages : []),
        ...(Array.isArray(framework?.transitivePackages) ? framework.transitivePackages : []),
      ];
      return packages.flatMap((rawPackage): ExternalCandidate[] => {
        const pkg = asRecord(rawPackage);
        if (!pkg) return [];
        const vulns = Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities : [];
        return vulns.flatMap((rawVuln): ExternalCandidate[] => {
          const vuln = asRecord(rawVuln);
          if (!vuln) return [];
          const id = stringValue(vuln.advisoryUrl) ?? stringValue(vuln.id) ?? stringValue(pkg.id) ?? "nuget";
          const identifiers = identifiersFromValues([id]);
          const packageName = stringValue(pkg.id) ?? "nuget-package";
          const version = stringValue(pkg.resolvedVersion) ?? stringValue(pkg.requestedVersion);
          return [{
            tool: "dotnet",
            title: `${packageName} has a known vulnerability`,
            category: "dependency",
            severity: npmSeverity(stringValue(vuln.severity)),
            confidence: "high",
            description: "dotnet reported a vulnerable NuGet package.",
            evidence: `${packageName}${version ? `@${version}` : ""} is affected by ${id}.`,
            remediation: `Upgrade ${packageName} to a non-vulnerable version.`,
            ruleId: `dotnet-vulnerable:${id}`,
            ...(hasIdentifiers(identifiers) ? { identifiers } : {}),
            package: packageInfo("nuget", packageName, version),
            ...(context.sourcePath ? { location: { file: normalizeFindingPath(context.sourcePath, context) } } : {}),
          }];
        });
      });
    });
  });
}

function parseSarif(tool: string, value: unknown, context: ParserContext): ExternalCandidate[] {
  const root = asRecord(value);
  const runs = Array.isArray(root?.runs) ? root.runs : [];
  return runs.flatMap((rawRun): ExternalCandidate[] => {
    const run = asRecord(rawRun);
    if (!run) return [];
    const results = Array.isArray(run?.results) ? run.results : [];
    const rules = new Map<string, Record<string, unknown>>();
    const driver = asRecord(asRecord(run?.tool)?.driver);
    for (const rawRule of Array.isArray(driver?.rules) ? driver.rules : []) {
      const rule = asRecord(rawRule);
      const id = stringValue(rule?.id);
      if (id && rule) rules.set(id, rule);
    }
    return results.flatMap((rawResult): ExternalCandidate[] => {
      const result = asRecord(rawResult);
      if (!result) return [];
      const ruleId = stringValue(result.ruleId) ?? "sarif";
      const rule = rules.get(ruleId);
      const location = firstSarifLocation(result);
      const file = normalizeFindingPath(location.file, context);
      const line = location.line;
      return [{
        tool,
        title: stringValue(asRecord(result.message)?.text) ?? stringValue(asRecord(rule?.shortDescription)?.text) ?? ruleId,
        category: tool === "flawfinder" ? "code" : "code",
        severity: sarifSeverity(result, rule),
        confidence: "medium",
        description: stringValue(asRecord(rule?.fullDescription)?.text) ?? "SARIF scanner reported a finding.",
        evidence: evidenceWithLocation(file, line, stringValue(asRecord(result.message)?.text) ?? ruleId),
        remediation: stringValue(asRecord(rule?.help)?.text) ?? "Review the scanner rule guidance.",
        ruleId,
        cwe: cwesFromUnknown(rule),
        ...(file ? { location: locationFor(file, line, undefined) } : {}),
      }];
    });
  });
}

function parseScannerText(scanner: ScannerCommandId, content: string, context: ParserContext): ExternalCandidate[] {
  if (scanner === "trufflehog" || scanner === "govulncheck") {
    const records = content.split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line) as unknown;
        } catch {
          return undefined;
        }
      })
      .filter((item): item is unknown => item !== undefined);
    if (records.length > 0) {
      return parseScannerValue(scanner, records, context);
    }
  }
  if (scanner === "cppcheck") {
    return content.split(/\r?\n/).flatMap((line): ExternalCandidate[] => {
      const match = /^(.*?):(\d+):(.*?):(.*?):(.*)$/.exec(line.trim());
      if (!match) return [];
      const file = normalizeFindingPath(match[1], context);
      const lineNumber = Number(match[2]);
      const ruleId = match[4] || "cppcheck";
      const message = match[5] || ruleId;
      return [{
        tool: "cppcheck",
        title: message,
        category: "code",
        severity: npmSeverity(match[3]),
        confidence: "medium",
        description: "Cppcheck reported a C/C++ source analysis issue.",
        evidence: evidenceWithLocation(file, Number.isFinite(lineNumber) ? lineNumber : undefined, message),
        remediation: "Review the C/C++ code and address the Cppcheck warning.",
        ruleId,
        ...(file ? { location: locationFor(file, Number.isFinite(lineNumber) ? lineNumber : undefined, undefined) } : {}),
      }];
    });
  }
  if (scanner === "spotbugs") {
    return parseSpotBugsXml(content, context);
  }
  return [];
}

function parseSpotBugsXml(content: string, context: ParserContext): ExternalCandidate[] {
  const findings: ExternalCandidate[] = [];
  const bugPattern = /<BugInstance\b([\s\S]*?)<\/BugInstance>/g;
  for (const match of content.matchAll(bugPattern)) {
    const bug = match[1] ?? "";
    const type = xmlAttr(bug, "type") ?? "spotbugs";
    const rank = Number(xmlAttr(bug, "rank") ?? "15");
    const sourceLine = /<SourceLine\b([^>]*)\/?>/.exec(bug)?.[1] ?? "";
    const file = normalizeFindingPath(xmlAttr(sourceLine, "sourcepath") ?? xmlAttr(sourceLine, "sourcefile"), context);
    const line = numberFromString(xmlAttr(sourceLine, "start"));
    const message = xmlText(bug, "LongMessage") ?? xmlText(bug, "ShortMessage") ?? type;
    findings.push({
      tool: "spotbugs",
      title: message,
      category: "code",
      severity: rank <= 4 ? "high" : rank <= 9 ? "medium" : "low",
      confidence: "medium",
      description: "FindSecBugs/SpotBugs reported a Java bytecode security issue.",
      evidence: evidenceWithLocation(file, line, message),
      remediation: "Review the affected Java code and apply the SpotBugs rule guidance.",
      ruleId: type,
      ...(file ? { location: locationFor(file, line, undefined) } : {}),
    });
  }
  return findings;
}

function firstSarifLocation(result: Record<string, unknown>): { file?: string; line?: number } {
  const locations = Array.isArray(result.locations) ? result.locations : [];
  const first = locations.length > 0 ? asRecord(locations[0]) : undefined;
  const physical = asRecord(first?.physicalLocation);
  const artifact = asRecord(physical?.artifactLocation);
  const region = asRecord(physical?.region);
  const file = stringValue(artifact?.uri);
  const line = numberValue(region?.startLine);
  return {
    ...(file ? { file } : {}),
    ...(line !== undefined ? { line } : {}),
  };
}

function sarifSeverity(result: Record<string, unknown>, rule?: Record<string, unknown>): Severity {
  const level = stringValue(result.level)?.toLowerCase();
  if (level === "error") return "high";
  if (level === "warning") return "medium";
  if (level === "note" || level === "none") return "info";
  const properties = asRecord(rule?.properties);
  return npmSeverity(stringValue(properties?.severity) ?? stringValue(properties?.problem_severity));
}

function gosecConfidence(value: string | undefined): Finding["confidence"] {
  switch (value?.toLowerCase()) {
    case "high":
      return "high";
    case "low":
      return "low";
    default:
      return "medium";
  }
}

function brakemanConfidence(value: number | undefined): Finding["confidence"] {
  if (value === 0) return "high";
  if (value === 2) return "low";
  return "medium";
}

function brakemanSeverity(value: number | undefined): Severity {
  if (value === 0) return "high";
  if (value === 2) return "low";
  return "medium";
}

function xmlAttr(value: string, name: string): string | undefined {
  const match = new RegExp(`${name}="([^"]*)"`).exec(value);
  return match?.[1] ? decodeXml(match[1]) : undefined;
}

function xmlText(value: string, tag: string): string | undefined {
  const match = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`).exec(value);
  return match?.[1] ? decodeXml(match[1].trim()) : undefined;
}

function decodeXml(value: string): string {
  return value
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function numberFromString(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
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
