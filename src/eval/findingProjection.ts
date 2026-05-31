import type { Finding } from "../shared/types.js";
import { normalizeCweList } from "./cweTolerance.js";
import { normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { normalizeEvalPath } from "./pathNormalize.js";
import type { ActualFindingProjection, EvalLocation } from "./schema.js";

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
