import type { Finding } from "../shared/types.js";
import { normalizeCweList } from "./cweTolerance.js";
import { normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { normalizeEvalPath } from "./pathNormalize.js";
import type { ActualFindingProjection, EvalLocation, IgnoredActualFinding } from "./schema.js";

export type FindingProjectionOptions = {
  fixtureRoot?: string;
};

export function projectFinding(
  finding: Finding,
  options: FindingProjectionOptions = {},
): ActualFindingProjection {
  const location = finding.location
    ? projectLocation(finding.location.file, finding.location.startLine, finding.location.endLine, options.fixtureRoot)
    : undefined;
  const ruleIds = normalizeIdentifierSet(
    [finding.ruleId, finding.tool].filter((value): value is string => typeof value === "string"),
    "rule",
  );

  return {
    id: finding.id,
    fingerprint: finding.fingerprint,
    category: finding.category,
    title: finding.title,
    severity: finding.severity,
    cwe: normalizeCweList(finding.cwe),
    identifiers: normalizeIdentifiers(finding.identifiers),
    ruleIds,
    ...(location ? { location } : {}),
    ...(finding.package ? { package: { ...finding.package } } : {}),
    ...(finding.tool ? { tool: finding.tool } : {}),
  };
}

export function projectFindings(
  findings: readonly Finding[],
  options: FindingProjectionOptions = {},
): ActualFindingProjection[] {
  return findings.map((finding) => projectFinding(finding, options));
}

export function dedupeActualFindings(
  findings: readonly ActualFindingProjection[],
): { findings: ActualFindingProjection[]; ignored: IgnoredActualFinding[] } {
  const selected = new Map<string, ActualFindingProjection>();
  const ignored: IgnoredActualFinding[] = [];

  for (const finding of [...findings].sort(compareActualForDedupe)) {
    const noiseKey = actualFindingNoiseKey(finding);
    const canonical = selected.get(noiseKey);
    if (!canonical) {
      selected.set(noiseKey, finding);
      continue;
    }

    ignored.push({
      id: finding.id,
      fingerprint: finding.fingerprint,
      category: finding.category,
      reason: "duplicate",
      duplicateOfId: canonical.id,
      duplicateOfFingerprint: canonical.fingerprint,
      noiseKey,
    });
  }

  return {
    findings: [...selected.values()].sort(compareActualForOutput),
    ignored: ignored.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

export function actualFindingNoiseKey(finding: ActualFindingProjection): string {
  const identifiers = [
    ...finding.identifiers.cve,
    ...finding.identifiers.ghsa,
    ...finding.identifiers.osv,
  ].sort();
  const advisoryKey = identifiers.length > 0 ? identifiers.join(",") : undefined;
  const packageKey = finding.package
    ? `${finding.package.ecosystem.toLowerCase()}:${finding.package.name.toLowerCase()}`
    : undefined;

  if (finding.category === "dependency" && packageKey) {
    return ["dependency", packageKey, advisoryKey ?? finding.ruleIds.join(",")].filter(Boolean).join("|");
  }

  const location = finding.location
    ? `${finding.location.path}:${finding.location.startLine ?? ""}:${finding.location.endLine ?? ""}`
    : "";
  const ruleKey = finding.ruleIds.length > 0 ? finding.ruleIds.join(",") : undefined;
  const cweKey = finding.cwe.length > 0 ? finding.cwe.join(",") : undefined;
  const semanticKey = advisoryKey ?? ruleKey ?? cweKey ?? normalizeTitle(finding.title);
  return [finding.category, location, semanticKey].join("|");
}

function projectLocation(
  file: string,
  startLine: number | undefined,
  endLine: number | undefined,
  fixtureRoot: string | undefined,
): EvalLocation {
  return {
    path: normalizeEvalPath(file, fixtureRoot),
    ...(typeof startLine === "number" ? { startLine } : {}),
    ...(typeof endLine === "number" ? { endLine } : {}),
  };
}

function compareActualForDedupe(left: ActualFindingProjection, right: ActualFindingProjection): number {
  return (
    severityRank[right.severity] - severityRank[left.severity] ||
    specificityScore(right) - specificityScore(left) ||
    left.fingerprint.localeCompare(right.fingerprint) ||
    left.id.localeCompare(right.id)
  );
}

function compareActualForOutput(left: ActualFindingProjection, right: ActualFindingProjection): number {
  return (
    (left.location?.path ?? "").localeCompare(right.location?.path ?? "") ||
    (left.location?.startLine ?? 0) - (right.location?.startLine ?? 0) ||
    left.category.localeCompare(right.category) ||
    left.fingerprint.localeCompare(right.fingerprint)
  );
}

function specificityScore(finding: ActualFindingProjection): number {
  return (
    finding.identifiers.cve.length * 4 +
    finding.identifiers.ghsa.length * 4 +
    finding.identifiers.osv.length * 4 +
    finding.ruleIds.length * 2 +
    finding.cwe.length +
    (finding.location ? 1 : 0) +
    (finding.package ? 1 : 0)
  );
}

function normalizeTitle(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().replace(/\s+/g, " ");
}

const severityRank: Record<Finding["severity"], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
