import path from "node:path";
import { toPosixPath } from "../shared/paths.js";
import { clampText, redactSecrets, stableId } from "../shared/text.js";
import type { Finding, FindingCategory, Severity } from "../shared/types.js";

const severityValues = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const confidenceValues = new Set<Finding["confidence"]>(["low", "medium", "high", "confirmed"]);
const categoryValues = new Set<FindingCategory>(["code", "dependency", "secret", "supply-chain", "config"]);

export function normalizeFindings(findings: readonly Finding[], repoRoot: string): Finding[] {
  return findings.map((finding) => normalizeFinding(finding, repoRoot));
}

export function normalizeFinding(finding: Finding, repoRoot: string): Finding {
  const tool = nonEmpty(finding.tool) ?? "hermsec";
  const category = categoryValues.has(finding.category) ? finding.category : "code";
  const severity = severityValues.has(finding.severity) ? finding.severity : "medium";
  const confidence = confidenceValues.has(finding.confidence) ? finding.confidence : "medium";
  const title = nonEmpty(finding.title) ?? "Security finding";
  const ruleId = nonEmpty(finding.ruleId) ?? `${tool}.${category}.finding`;
  const location = normalizeLocation(finding.location, repoRoot);
  const evidence = clampText(redactSecrets(nonEmpty(finding.evidence) ?? evidenceFallback(location, title)), 900);
  const description = clampText(nonEmpty(finding.description) ?? "A scanner reported a security-relevant condition.", 900);
  const remediation = clampText(nonEmpty(finding.remediation) ?? "Review the scanner evidence and apply the recommended defensive change.", 900);
  const fingerprintSource = JSON.stringify({
    tool,
    ruleId,
    category,
    severity,
    file: location?.file,
    line: location?.startLine,
    package: finding.package,
    title,
    identifiers: finding.identifiers,
    cwe: finding.cwe,
  });
  const fingerprint = nonEmpty(finding.fingerprint) ?? stableId(fingerprintSource, "fp");
  const normalized: Finding = {
    ...finding,
    id: nonEmpty(finding.id) ?? stableId(fingerprintSource, "finding"),
    title,
    category,
    severity,
    confidence,
    description,
    evidence,
    remediation,
    tool,
    ruleId,
    fingerprint,
  };
  if (location) {
    normalized.location = location;
  } else {
    delete normalized.location;
  }
  return normalized;
}

function normalizeLocation(location: Finding["location"], repoRoot: string): Finding["location"] | undefined {
  if (!location?.file) {
    return undefined;
  }
  const file = normalizePath(location.file, repoRoot);
  if (!file) {
    return undefined;
  }
  return {
    file,
    ...(validLine(location.startLine) ? { startLine: location.startLine } : {}),
    ...(validLine(location.endLine) ? { endLine: location.endLine } : {}),
  };
}

function normalizePath(value: string, repoRoot: string): string {
  const normalizedRoot = path.resolve(repoRoot);
  const normalizedValue = path.isAbsolute(value) ? path.resolve(value) : path.resolve(repoRoot, value);
  const relative = path.relative(normalizedRoot, normalizedValue);
  if (!relative.startsWith("..") && !path.isAbsolute(relative)) {
    return toPosixPath(relative);
  }
  return toPosixPath(value);
}

function validLine(value: number | undefined): value is number {
  return value !== undefined && Number.isInteger(value) && value > 0;
}

function evidenceFallback(location: Finding["location"] | undefined, title: string): string {
  return location?.file
    ? `${location.file}${location.startLine ? `:${location.startLine}` : ""} ${title}`
    : title;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
