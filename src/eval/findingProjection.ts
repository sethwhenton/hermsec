import type { Finding } from "../shared/types.js";
import { normalizeCweList } from "./cweTolerance.js";
import { normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { normalizeEvalPath } from "./pathNormalize.js";
import type { ActualFindingProjection, EvalLocation, IgnoredActualFinding } from "./schema.js";
import {
  inferPrimaryVulnerabilityClass,
  resolveVulnerabilityClasses,
} from "./vulnerabilityClass.js";

export type FindingProjectionOptions = {
  fixtureRoot?: string;
};

export type ActualFindingDedupeOptions = {
  fingerprintSensitive?: boolean;
};

export function projectFinding(
  finding: Finding,
  options: FindingProjectionOptions = {},
): ActualFindingProjection {
  const location = finding.location
    ? projectLocation(finding.location.file, finding.location.startLine, finding.location.endLine, options.fixtureRoot)
    : undefined;
  const sourceLocations = finding.sourceLocations?.map((source) =>
    projectLocation(
      source.file,
      source.startLine,
      source.endLine,
      options.fixtureRoot,
    ),
  );
  const ruleIds = normalizeIdentifierSet(
    [finding.ruleId, finding.tool].filter((value): value is string => typeof value === "string"),
    "rule",
  );

  const projection: ActualFindingProjection = {
    id: finding.id,
    fingerprint: finding.fingerprint,
    category: finding.category,
    title: finding.title,
    severity: finding.severity,
    cwe: normalizeCweList(finding.cwe),
    identifiers: normalizeIdentifiers(finding.identifiers),
    ruleIds,
    ...(location ? { location } : {}),
    ...(sourceLocations && sourceLocations.length > 0
      ? { sourceLocations: sourceLocations.sort(compareLocations) }
      : {}),
    ...(finding.package ? { package: { ...finding.package } } : {}),
    ...(finding.tool ? { tool: finding.tool } : {}),
    ...(finding.agent?.judge?.verdict
      ? { disposition: finding.agent.judge.verdict }
      : {}),
  };
  const vulnerabilityClass = inferPrimaryVulnerabilityClass(projection);
  return vulnerabilityClass ? { ...projection, vulnerabilityClass } : projection;
}

export function projectFindings(
  findings: readonly Finding[],
  options: FindingProjectionOptions = {},
): ActualFindingProjection[] {
  return findings.map((finding) => projectFinding(finding, options));
}

export function dedupeActualFindings(
  findings: readonly ActualFindingProjection[],
  options: ActualFindingDedupeOptions = {},
): { findings: ActualFindingProjection[]; ignored: IgnoredActualFinding[] } {
  const selected = new Map<string, ActualFindingProjection>();
  const ignored: IgnoredActualFinding[] = [];

  for (const finding of [...findings].sort(compareActualForDedupe)) {
    const noiseKey = actualFindingNoiseKey(finding, options);
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

export function actualFindingNoiseKey(
  finding: ActualFindingProjection,
  options: ActualFindingDedupeOptions = {},
): string {
  const identifiers = [
    ...finding.identifiers.cve,
    ...finding.identifiers.ghsa,
    ...finding.identifiers.osv,
  ].sort();
  const advisoryKey = identifiers.length > 0 ? identifiers.join(",") : undefined;
  const packageKey = finding.package
    ? `${finding.package.ecosystem.toLowerCase()}:${finding.package.name.toLowerCase()}`
    : undefined;
  const vulnerabilityClassKey =
    resolveVulnerabilityClasses(finding).join(",") || "<unclassified>";
  const fingerprintKey =
    options.fingerprintSensitive === false ? "" : finding.fingerprint;

  if (finding.category === "dependency" && packageKey) {
    return [
      "dependency",
      packageKey,
      vulnerabilityClassKey,
      fingerprintKey,
      advisoryKey ?? finding.ruleIds.join(","),
    ]
      .filter(Boolean)
      .join("|");
  }

  const location = finding.location
    ? `${finding.location.path}:${finding.location.startLine ?? ""}:${finding.location.endLine ?? ""}`
    : "";
  const sourceLocations = (finding.sourceLocations ?? [])
    .map(
      (source) =>
        `${source.path}:${source.startLine ?? ""}:${source.endLine ?? ""}`,
    )
    .sort()
    .join(",");
  const ruleKey = finding.ruleIds.length > 0 ? finding.ruleIds.join(",") : undefined;
  const cweKey = finding.cwe.length > 0 ? finding.cwe.join(",") : undefined;
  const semanticKey =
    advisoryKey ??
    ruleKey ??
    cweKey ??
    finding.vulnerabilityClass ??
    normalizeTitle(finding.title);
  return [
    finding.category,
    vulnerabilityClassKey,
    location,
    sourceLocations,
    fingerprintKey,
    semanticKey,
  ].join("|");
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
    specificityScore(right) - specificityScore(left) ||
    vulnerabilityClassSignature(left).localeCompare(
      vulnerabilityClassSignature(right),
    ) ||
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
    (finding.sourceLocations?.length ?? 0) +
    (finding.package ? 1 : 0)
  );
}

function compareLocations(left: EvalLocation, right: EvalLocation): number {
  return (
    left.path.localeCompare(right.path) ||
    (left.startLine ?? 0) - (right.startLine ?? 0) ||
    (left.endLine ?? 0) - (right.endLine ?? 0)
  );
}

function normalizeTitle(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().replace(/\s+/g, " ");
}

function vulnerabilityClassSignature(
  finding: ActualFindingProjection,
): string {
  return resolveVulnerabilityClasses(finding).join(",");
}
