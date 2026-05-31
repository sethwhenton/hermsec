import { scoreCweMatch } from "./cweTolerance.js";
import { dedupeActualFindings } from "./findingProjection.js";
import { identifierOverlap, normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { pathMatches } from "./pathNormalize.js";
import { scoreSeverity } from "./severityTolerance.js";
import {
  DEFAULT_MATCH_THRESHOLDS,
  type AcceptedMatch,
  type ActualFindingProjection,
  type CandidateSignal,
  type EvalFindingCategory,
  type GroundTruthFinding,
  type MatchCandidate,
  type MatchResult,
  type MatchThresholds,
} from "./schema.js";

export function scoreCandidate(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds = DEFAULT_MATCH_THRESHOLDS,
): MatchCandidate {
  const signals: CandidateSignal[] = [];
  addSignal(signals, scoreCategory(expected.category, actual.category));
  addSignal(signals, scoreAdvisories(expected, actual));
  addSignal(signals, scorePackage(expected, actual));
  addSignal(signals, scoreLocation(expected, actual, thresholds));
  addSignal(signals, scoreRules(expected, actual));
  addSignal(signals, {
    name: "cwe",
    ...scoreCweMatch(
      expected.cwe,
      actual.cwe,
      expected.aliases ?? [],
      expected.matchHints?.cweTolerance ?? thresholds.cweTolerance,
    ),
  });
  addSignal(signals, {
    name: "severity",
    ...scoreSeverity(
      expected.severity,
      actual.severity,
      expected.matchHints?.severityTolerance ?? thresholds.severityTolerance,
    ),
  });

  const score = signals.reduce((total, signal) => total + signal.points, 0);

  return {
    expectedId: expected.id,
    actualId: actual.id,
    actualFingerprint: actual.fingerprint,
    expectedCategory: expected.category,
    actualCategory: actual.category,
    score,
    signals,
    ...(expected.location ? { expectedPath: expected.location.path } : {}),
    ...(actual.location ? { actualPath: actual.location.path } : {}),
  };
}

export function matchFindings(
  expected: readonly GroundTruthFinding[],
  actual: readonly ActualFindingProjection[],
  thresholds: MatchThresholds = DEFAULT_MATCH_THRESHOLDS,
): MatchResult {
  const dedupedActual = dedupeActualFindings(actual);
  const candidates = expected
    .flatMap((expectedFinding) =>
      dedupedActual.findings.map((actualFinding) => scoreCandidate(expectedFinding, actualFinding, thresholds)),
    )
    .sort(compareCandidates);

  const matches: AcceptedMatch[] = [];
  const usedExpected = new Set<string>();
  const usedActual = new Set<string>();
  const acceptedKeys = new Set<string>();

  for (const candidate of candidates) {
    if (candidate.score < thresholds.minMatchScore) {
      continue;
    }

    if (usedExpected.has(candidate.expectedId) || usedActual.has(candidate.actualFingerprint)) {
      continue;
    }

    matches.push({ ...candidate, accepted: true });
    usedExpected.add(candidate.expectedId);
    usedActual.add(candidate.actualFingerprint);
    acceptedKeys.add(candidateKey(candidate));
  }

  const falsePositives = dedupedActual.findings.filter((finding) => !usedActual.has(finding.fingerprint));
  const falseNegatives = expected.filter((finding) => !usedExpected.has(finding.id));

  return {
    matches,
    rejectedCandidates: candidates.filter((candidate) => !acceptedKeys.has(candidateKey(candidate))),
    falsePositives,
    falseNegatives,
    ignoredActual: dedupedActual.ignored,
    trueNegative: expected.length === 0 && dedupedActual.findings.length === 0,
    thresholds,
  };
}

export async function explainMatch(options: {
  cwd: string;
  suite?: string;
  caseId: string;
  findingId: string;
}) {
  return {
    ok: true as const,
    message: `Match explanation requested for case ${options.caseId} and finding ${options.findingId}.`,
    data: {
      suite: options.suite,
      caseId: options.caseId,
      findingId: options.findingId,
      rule: "Hermsec uses deterministic one-to-one matching by category, path, line tolerance, CWE/advisory overlap, package identity, rule identity, and severity tolerance.",
    },
  };
}

function scoreCategory(expected: EvalFindingCategory, actual: EvalFindingCategory): CandidateSignal {
  if (expected !== actual) {
    return { name: "category", points: 0, explanation: "category differs" };
  }

  return {
    name: "category",
    points: expected === "secret" ? 20 : 15,
    explanation: "category matches",
  };
}

function scoreAdvisories(expected: GroundTruthFinding, actual: ActualFindingProjection): CandidateSignal {
  const overlap = identifierOverlap(
    normalizeIdentifiers(expected.identifiers),
    normalizeIdentifiers(actual.identifiers),
    expected.aliases,
  );
  if (overlap.length === 0) {
    return { name: "advisory", points: 0, explanation: "no advisory identifier overlap" };
  }

  const points = expected.category === "dependency" ? 45 : 15;
  return {
    name: "advisory",
    points,
    explanation: `advisory identifier overlaps: ${overlap.join(", ")}`,
  };
}

function scorePackage(expected: GroundTruthFinding, actual: ActualFindingProjection): CandidateSignal {
  if (expected.category !== "dependency") {
    return { name: "package", points: 0, explanation: "package matching is not required" };
  }

  if (!expected.package || !actual.package) {
    return { name: "package", points: 0, explanation: "package metadata is missing" };
  }

  const ecosystemMatches = expected.package.ecosystem.toLowerCase() === actual.package.ecosystem.toLowerCase();
  const nameMatches = expected.package.name.toLowerCase() === actual.package.name.toLowerCase();
  if (!ecosystemMatches || !nameMatches) {
    return { name: "package", points: 0, explanation: "package ecosystem or name differs" };
  }

  return { name: "package", points: 30, explanation: "package ecosystem and name match" };
}

function scoreLocation(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): CandidateSignal {
  if (!expected.location || !actual.location) {
    return { name: "location", points: 0, explanation: "location metadata is missing" };
  }

  const samePath = pathMatches(expected.location.path, actual.location.path);
  if (!samePath) {
    return { name: "location", points: 0, explanation: "file path differs" };
  }

  const basePoints = expected.category === "secret" ? 25 : expected.category === "code" ? 25 : 30;
  const linePoints = scoreLine(expected, actual, thresholds);
  return {
    name: "location",
    points: basePoints + linePoints.points,
    explanation: linePoints.points > 0 ? `file path matches; ${linePoints.explanation}` : "file path matches",
  };
}

function scoreLine(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): CandidateSignal {
  const expectedRange = toLineRange(expected.location?.startLine, expected.location?.endLine);
  const actualRange = toLineRange(actual.location?.startLine, actual.location?.endLine);
  if (!expectedRange || !actualRange) {
    return { name: "line", points: 0, explanation: "line metadata is missing" };
  }

  if (rangesOverlap(expectedRange, actualRange)) {
    const points = expected.category === "secret" ? 15 : expected.category === "code" ? 20 : 10;
    return { name: "line", points, explanation: "line ranges overlap" };
  }

  const tolerance = expected.matchHints?.lineTolerance ?? thresholds.defaultLineTolerance;
  if (rangeDistance(expectedRange, actualRange) <= tolerance) {
    const points = expected.category === "secret" ? 8 : expected.category === "code" ? 12 : 6;
    return { name: "line", points, explanation: "line is within configured tolerance" };
  }

  return { name: "line", points: 0, explanation: "line is outside configured tolerance" };
}

function scoreRules(expected: GroundTruthFinding, actual: ActualFindingProjection): CandidateSignal {
  const expectedRules = normalizeIdentifierSet([...(expected.ruleIds ?? []), ...(expected.aliases ?? [])], "rule");
  const actualRules = normalizeIdentifierSet(actual.ruleIds, "rule");
  const overlap = actualRules.filter((rule) => expectedRules.includes(rule));
  if (overlap.length === 0) {
    return { name: "rule", points: 0, explanation: "no scanner or rule ID overlap" };
  }

  const points = expected.category === "dependency" ? 10 : 20;
  return { name: "rule", points, explanation: `scanner or rule ID overlaps: ${overlap.join(", ")}` };
}

function addSignal(signals: CandidateSignal[], signal: CandidateSignal): void {
  if (signal.points > 0) {
    signals.push(signal);
  }
}

function compareCandidates(left: MatchCandidate, right: MatchCandidate): number {
  return (
    right.score - left.score ||
    left.expectedId.localeCompare(right.expectedId) ||
    left.actualFingerprint.localeCompare(right.actualFingerprint) ||
    left.actualCategory.localeCompare(right.actualCategory) ||
    (left.actualPath ?? "").localeCompare(right.actualPath ?? "")
  );
}

function candidateKey(candidate: MatchCandidate): string {
  return `${candidate.expectedId}\0${candidate.actualFingerprint}`;
}

function toLineRange(startLine: number | undefined, endLine: number | undefined) {
  if (typeof startLine !== "number") {
    return undefined;
  }

  const end = typeof endLine === "number" ? endLine : startLine;
  return {
    start: Math.min(startLine, end),
    end: Math.max(startLine, end),
  };
}

function rangesOverlap(
  left: { start: number; end: number },
  right: { start: number; end: number },
): boolean {
  return left.start <= right.end && right.start <= left.end;
}

function rangeDistance(left: { start: number; end: number }, right: { start: number; end: number }): number {
  if (rangesOverlap(left, right)) {
    return 0;
  }

  return left.end < right.start ? right.start - left.end : left.start - right.end;
}
