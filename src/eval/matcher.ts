import { scoreCweMatch } from "./cweTolerance.js";
import {
  actualFindingNoiseKey,
  dedupeActualFindings,
} from "./findingProjection.js";
import {
  identifierOverlap,
  normalizeIdentifiers,
  normalizeIdentifierSet,
} from "./identifierNormalize.js";
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
import {
  inferPrimaryVulnerabilityClass,
  vulnerabilityClassesCompatible,
} from "./vulnerabilityClass.js";

/**
 * Bounds raw caller-controlled arrays before dedupe, sorting, indexing, or
 * candidate construction. This permits noisy scanner output while preventing
 * unbounded preprocessing work.
 */
export const MATCH_RAW_INPUT_FINDING_LIMIT = 4_096;

/**
 * Bounds the deterministic Hungarian assignment matrix after actual findings
 * have been deduplicated.
 */
export const MATCH_ASSIGNMENT_FINDING_LIMIT = 256;

export class MatchRawInputCapacityError extends Error {
  readonly code = "eval-raw-input-capacity-exceeded";

  constructor(expectedCount: number, actualCount: number) {
    super(
      `Evaluation matching accepts at most ${MATCH_RAW_INPUT_FINDING_LIMIT} raw expected and ${MATCH_RAW_INPUT_FINDING_LIMIT} raw actual findings per case before preprocessing; received ${expectedCount} expected and ${actualCount} actual.`,
    );
    this.name = "MatchRawInputCapacityError";
  }
}

export class MatchAssignmentCapacityError extends Error {
  readonly code = "eval-assignment-capacity-exceeded";

  constructor(expectedCount: number, actualCount: number) {
    super(
      `Evaluation matching supports at most ${MATCH_ASSIGNMENT_FINDING_LIMIT} expected and ${MATCH_ASSIGNMENT_FINDING_LIMIT} deduplicated actual findings per case; received ${expectedCount} expected and ${actualCount} actual.`,
    );
    this.name = "MatchAssignmentCapacityError";
  }
}

export function scoreCandidate(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds = DEFAULT_MATCH_THRESHOLDS,
): MatchCandidate {
  const signals: CandidateSignal[] = [];
  const categorySignal = scoreCategory(expected.category, actual.category);
  const classSignal = scoreVulnerabilityClass(expected, actual);
  const advisorySignal = scoreAdvisories(expected, actual);
  const packageSignal = scorePackage(expected, actual);
  const locationSignal = scoreLocation(expected, actual, thresholds);
  const sourceSignal = scoreSourceEvidence(expected, actual, thresholds);
  const ruleSignal = scoreRules(expected, actual);
  const cweSignal: CandidateSignal = {
    name: "cwe",
    ...scoreCweMatch(
      expected.cwe,
      actual.cwe,
      expected.aliases ?? [],
      expected.matchHints?.cweTolerance ?? thresholds.cweTolerance,
    ),
  };
  const severityAgreement = scoreSeverity(
    expected.severity,
    actual.severity,
    expected.matchHints?.severityTolerance ?? thresholds.severityTolerance,
  );
  const severitySignal: CandidateSignal = {
    name: "severity",
    points: 0,
    explanation: severityAgreement.explanation,
  };

  signals.push(
    categorySignal,
    classSignal,
    advisorySignal,
    packageSignal,
    locationSignal,
    sourceSignal,
    ruleSignal,
    cweSignal,
    severitySignal,
  );

  const eligibility = evaluateEligibility(expected, actual, thresholds);
  const evidenceScore = signals
    .filter((signal) => signal.name !== "severity")
    .reduce((total, signal) => total + signal.points, 0);

  return {
    expectedId: expected.id,
    actualId: actual.id,
    actualFingerprint: actual.fingerprint,
    expectedCategory: expected.category,
    actualCategory: actual.category,
    ...(actual.disposition ? { actualDisposition: actual.disposition } : {}),
    ...(inferPrimaryVulnerabilityClass(expected)
      ? {
          expectedVulnerabilityClass:
            inferPrimaryVulnerabilityClass(expected) as string,
        }
      : {}),
    ...(inferPrimaryVulnerabilityClass(actual)
      ? {
          actualVulnerabilityClass:
            inferPrimaryVulnerabilityClass(actual) as string,
        }
      : {}),
    score: evidenceScore,
    evidenceScore,
    eligible: eligibility.reasons.length === 0,
    rejectionReasons: eligibility.reasons,
    signals,
    ...(expected.location ? { expectedPath: expected.location.path } : {}),
    ...(actual.location ? { actualPath: actual.location.path } : {}),
  };
}

export function matchFindings(
  expected: readonly GroundTruthFinding[],
  actual: readonly ActualFindingProjection[],
  thresholds: MatchThresholds = DEFAULT_MATCH_THRESHOLDS,
  options: { dedupeMode?: "strict" | "legacy" } = {},
): MatchResult {
  if (
    expected.length > MATCH_RAW_INPUT_FINDING_LIMIT ||
    actual.length > MATCH_RAW_INPUT_FINDING_LIMIT
  ) {
    throw new MatchRawInputCapacityError(expected.length, actual.length);
  }

  const dedupedActual = dedupeActualFindings(actual, {
    fingerprintSensitive: options.dedupeMode !== "legacy",
  });
  const orderedExpected = [...expected].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
  const orderedActual = [...dedupedActual.findings].sort(
    compareActualForAssignment,
  );
  if (
    orderedExpected.length > MATCH_ASSIGNMENT_FINDING_LIMIT ||
    orderedActual.length > MATCH_ASSIGNMENT_FINDING_LIMIT
  ) {
    throw new MatchAssignmentCapacityError(
      orderedExpected.length,
      orderedActual.length,
    );
  }
  const candidateMatrix = orderedExpected.map((expectedFinding) =>
    orderedActual.map((actualFinding) =>
      scoreCandidate(expectedFinding, actualFinding, thresholds),
    ),
  );
  const weights = candidateMatrix.map((row) =>
    row.map((candidate) => {
      if (
        !candidate.eligible ||
        candidate.evidenceScore < thresholds.minMatchScore
      ) {
        return 0;
      }
      return candidate.evidenceScore;
    }),
  );
  const assignment = maximumWeightOneToOne(weights);
  const matches: AcceptedMatch[] = [];
  const usedExpectedIndexes = new Set<number>();
  const usedActualIndexes = new Set<number>();
  const acceptedCoordinates = new Set<string>();

  for (const [expectedIndex, actualIndex] of assignment) {
    const candidate = candidateMatrix[expectedIndex]?.[actualIndex];
    if (
      !candidate?.eligible ||
      candidate.evidenceScore < thresholds.minMatchScore
    ) {
      continue;
    }

    matches.push({ ...candidate, accepted: true });
    usedExpectedIndexes.add(expectedIndex);
    usedActualIndexes.add(actualIndex);
    acceptedCoordinates.add(`${expectedIndex}\0${actualIndex}`);
  }
  matches.sort(compareCandidates);

  const falsePositives = orderedActual.filter(
    (_finding, index) => !usedActualIndexes.has(index),
  );
  const falseNegatives = orderedExpected.filter(
    (_finding, index) => !usedExpectedIndexes.has(index),
  );
  const rejectedCandidates = candidateMatrix
    .flatMap((row, expectedIndex) =>
      row.filter(
        (_candidate, actualIndex) =>
          !acceptedCoordinates.has(`${expectedIndex}\0${actualIndex}`),
      ),
    )
    .sort(compareCandidates);

  return {
    matches,
    rejectedCandidates,
    falsePositives,
    falseNegatives,
    ignoredActual: dedupedActual.ignored,
    trueNegative:
      expected.length === 0 && dedupedActual.findings.length === 0,
    thresholds,
  };
}

/**
 * Returns [row, column] pairs for a deterministic maximum-weight assignment.
 * Zero-weight pairs are omitted so callers can represent unmatched rows/columns.
 */
export function maximumWeightOneToOne(
  weights: readonly (readonly number[])[],
): Array<readonly [number, number]> {
  const rowCount = weights.length;
  const columnCount = weights.reduce(
    (largest, row) => Math.max(largest, row.length),
    0,
  );
  const size = Math.max(rowCount, columnCount);
  if (size === 0) {
    return [];
  }

  const maxWeight = weights.reduce(
    (largest, row) =>
      Math.max(
        largest,
        ...row.map((weight) =>
          Number.isFinite(weight) && weight > 0 ? weight : 0,
        ),
      ),
    0,
  );
  if (maxWeight === 0) {
    return [];
  }

  const cost = Array.from({ length: size }, (_, rowIndex) =>
    Array.from({ length: size }, (_, columnIndex) => {
      const weight =
        rowIndex < rowCount && columnIndex < (weights[rowIndex]?.length ?? 0)
          ? (weights[rowIndex]?.[columnIndex] ?? 0)
          : 0;
      return maxWeight - (Number.isFinite(weight) && weight > 0 ? weight : 0);
    }),
  );

  // Hungarian algorithm for a square minimum-cost assignment.
  const u = new Array<number>(size + 1).fill(0);
  const v = new Array<number>(size + 1).fill(0);
  const p = new Array<number>(size + 1).fill(0);
  const way = new Array<number>(size + 1).fill(0);

  for (let row = 1; row <= size; row += 1) {
    p[0] = row;
    let column0 = 0;
    const minValues = new Array<number>(size + 1).fill(
      Number.POSITIVE_INFINITY,
    );
    const used = new Array<boolean>(size + 1).fill(false);

    do {
      used[column0] = true;
      const row0 = p[column0] ?? 0;
      let delta = Number.POSITIVE_INFINITY;
      let column1 = 0;

      for (let column = 1; column <= size; column += 1) {
        if (used[column]) {
          continue;
        }
        const reducedCost =
          (cost[row0 - 1]?.[column - 1] ?? maxWeight) -
          (u[row0] ?? 0) -
          (v[column] ?? 0);
        if (reducedCost < (minValues[column] ?? Number.POSITIVE_INFINITY)) {
          minValues[column] = reducedCost;
          way[column] = column0;
        }
        const candidateMin =
          minValues[column] ?? Number.POSITIVE_INFINITY;
        if (
          candidateMin < delta ||
          (candidateMin === delta && column < column1)
        ) {
          delta = candidateMin;
          column1 = column;
        }
      }

      for (let column = 0; column <= size; column += 1) {
        if (used[column]) {
          const assignedRow = p[column] ?? 0;
          u[assignedRow] = (u[assignedRow] ?? 0) + delta;
          v[column] = (v[column] ?? 0) - delta;
        } else {
          minValues[column] =
            (minValues[column] ?? Number.POSITIVE_INFINITY) - delta;
        }
      }
      column0 = column1;
    } while ((p[column0] ?? 0) !== 0);

    do {
      const previousColumn = way[column0] ?? 0;
      p[column0] = p[previousColumn] ?? 0;
      column0 = previousColumn;
    } while (column0 !== 0);
  }

  const assignment: Array<readonly [number, number]> = [];
  for (let column = 1; column <= size; column += 1) {
    const row = (p[column] ?? 0) - 1;
    const actualColumn = column - 1;
    if (
      row >= 0 &&
      row < rowCount &&
      actualColumn < columnCount &&
      (weights[row]?.[actualColumn] ?? 0) > 0
    ) {
      assignment.push([row, actualColumn]);
    }
  }

  return assignment.sort(
    (left, right) => left[0] - right[0] || left[1] - right[1],
  );
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
      rule: "Hermsec requires compatible category and vulnerability class plus concrete location or package/advisory evidence, then computes a deterministic maximum-weight one-to-one assignment. Severity is evaluated separately and cannot create a detection match.",
    },
  };
}

function evaluateEligibility(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): { reasons: string[] } {
  const reasons: string[] = [];
  if (expected.category !== actual.category) {
    reasons.push("category-mismatch");
  }

  if (
    !vulnerabilityClassesCompatible(
      expected,
      actual,
      expected.matchPolicy?.vulnerabilityClass ?? "compatible",
    )
  ) {
    reasons.push("vulnerability-class-mismatch");
  }

  if (expected.category === "dependency") {
    if (!packagesMatch(expected, actual)) {
      reasons.push("package-evidence-missing");
    }
    if (
      !expected.matchHints?.advisoryMatchOptional &&
      !advisoriesMatch(expected, actual)
    ) {
      reasons.push("advisory-evidence-missing");
    }
    return { reasons };
  }

  const locationRequired = expected.matchPolicy
    ? expected.matchPolicy.location === "required"
    : expected.location !== undefined;
  const lineRequired = expected.matchPolicy
    ? expected.matchPolicy.line === "required"
    : typeof expected.location?.startLine === "number";
  if (locationRequired && !pathsMatch(expected, actual)) {
    reasons.push("location-evidence-mismatch");
  } else if (
    !expected.matchPolicy &&
    !locationRequired &&
    !pathsMatch(expected, actual) &&
    !rulesMatch(expected, actual)
  ) {
    reasons.push("location-or-rule-evidence-missing");
  }

  if (lineRequired && !linesMatch(expected, actual, thresholds)) {
    reasons.push("line-evidence-mismatch");
  }
  if (
    expected.evidence?.type === "source-and-sink" &&
    !sourceEvidenceMatches(expected, actual, thresholds)
  ) {
    reasons.push("source-evidence-mismatch");
  }

  return { reasons: [...new Set(reasons)].sort() };
}

function scoreCategory(
  expected: EvalFindingCategory,
  actual: EvalFindingCategory,
): CandidateSignal {
  if (expected !== actual) {
    return { name: "category", points: 0, explanation: "category differs" };
  }

  return {
    name: "category",
    points: expected === "secret" ? 20 : 15,
    explanation: "category matches",
  };
}

function scoreVulnerabilityClass(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): CandidateSignal {
  if (
    !vulnerabilityClassesCompatible(
      expected,
      actual,
      expected.matchPolicy?.vulnerabilityClass ?? "compatible",
    )
  ) {
    return {
      name: "vulnerability-class",
      points: 0,
      explanation: "vulnerability class differs or is unavailable",
    };
  }

  return {
    name: "vulnerability-class",
    points: 30,
    explanation: "vulnerability class is compatible",
  };
}

function scoreAdvisories(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): CandidateSignal {
  const overlap = identifierOverlap(
    normalizeIdentifiers(expected.identifiers),
    normalizeIdentifiers(actual.identifiers),
    expected.aliases,
  );
  if (overlap.length === 0) {
    return {
      name: "advisory",
      points: 0,
      explanation: "no advisory identifier overlap",
    };
  }

  const points = expected.category === "dependency" ? 45 : 15;
  return {
    name: "advisory",
    points,
    explanation: `advisory identifier overlaps: ${overlap.join(", ")}`,
  };
}

function scorePackage(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): CandidateSignal {
  if (expected.category !== "dependency") {
    return {
      name: "package",
      points: 0,
      explanation: "package matching is not required",
    };
  }

  if (!packagesMatch(expected, actual)) {
    return {
      name: "package",
      points: 0,
      explanation: "package ecosystem or name differs",
    };
  }

  return {
    name: "package",
    points: 30,
    explanation: "package ecosystem and name match",
  };
}

function scoreLocation(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): CandidateSignal {
  if (!expected.location || !actual.location) {
    return {
      name: "location",
      points: 0,
      explanation: "location metadata is missing",
    };
  }

  if (!pathMatches(expected.location.path, actual.location.path)) {
    return {
      name: "location",
      points: 0,
      explanation: "file path differs",
    };
  }

  const basePoints =
    expected.category === "secret" || expected.category === "code" ? 25 : 30;
  const linePoints = scoreLine(expected, actual, thresholds);
  return {
    name: "location",
    points: basePoints + linePoints.points,
    explanation:
      linePoints.points > 0
        ? `file path matches; ${linePoints.explanation}`
        : "file path matches",
  };
}

function scoreLine(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): CandidateSignal {
  const expectedRange = toLineRange(
    expected.location?.startLine,
    expected.location?.endLine,
  );
  const actualRange = toLineRange(
    actual.location?.startLine,
    actual.location?.endLine,
  );
  if (!expectedRange || !actualRange) {
    return {
      name: "line",
      points: 0,
      explanation: "line metadata is missing",
    };
  }

  if (rangesOverlap(expectedRange, actualRange)) {
    const points =
      expected.category === "secret"
        ? 15
        : expected.category === "code"
          ? 20
          : 10;
    return {
      name: "line",
      points,
      explanation: "line ranges overlap",
    };
  }

  const tolerance = effectiveLineTolerance(expected, thresholds);
  if (rangeDistance(expectedRange, actualRange) <= tolerance) {
    const points =
      expected.category === "secret"
        ? 8
        : expected.category === "code"
          ? 12
          : 6;
    return {
      name: "line",
      points,
      explanation: "line is within configured tolerance",
    };
  }

  return {
    name: "line",
    points: 0,
    explanation: "line is outside configured tolerance",
  };
}

function scoreSourceEvidence(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): CandidateSignal {
  if (expected.evidence?.type !== "source-and-sink") {
    return {
      name: "source-evidence",
      points: 0,
      explanation: "source evidence is not required",
    };
  }
  if (!sourceEvidenceMatches(expected, actual, thresholds)) {
    return {
      name: "source-evidence",
      points: 0,
      explanation: "source location evidence is missing or incompatible",
    };
  }
  return {
    name: "source-evidence",
    points: 20,
    explanation: "at least one expected source location is evidenced",
  };
}

function scoreRules(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): CandidateSignal {
  const overlap = ruleOverlap(expected, actual);
  if (overlap.length === 0) {
    return {
      name: "rule",
      points: 0,
      explanation: "no scanner or rule ID overlap",
    };
  }

  const points = expected.category === "dependency" ? 10 : 20;
  return {
    name: "rule",
    points,
    explanation: `scanner or rule ID overlaps: ${overlap.join(", ")}`,
  };
}

function advisoriesMatch(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): boolean {
  return (
    identifierOverlap(
      normalizeIdentifiers(expected.identifiers),
      normalizeIdentifiers(actual.identifiers),
      expected.aliases,
    ).length > 0
  );
}

function packagesMatch(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): boolean {
  if (!expected.package || !actual.package) {
    return false;
  }
  return (
    expected.package.ecosystem.toLowerCase() ===
      actual.package.ecosystem.toLowerCase() &&
    expected.package.name.toLowerCase() === actual.package.name.toLowerCase()
  );
}

function pathsMatch(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): boolean {
  return (
    expected.location !== undefined &&
    actual.location !== undefined &&
    pathMatches(expected.location.path, actual.location.path)
  );
}

function linesMatch(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): boolean {
  const expectedRange = toLineRange(
    expected.location?.startLine,
    expected.location?.endLine,
  );
  const actualRange = toLineRange(
    actual.location?.startLine,
    actual.location?.endLine,
  );
  if (!expectedRange || !actualRange) {
    return false;
  }
  const tolerance = effectiveLineTolerance(expected, thresholds);
  return (
    rangesOverlap(expectedRange, actualRange) ||
    rangeDistance(expectedRange, actualRange) <= tolerance
  );
}

function sourceEvidenceMatches(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
  thresholds: MatchThresholds,
): boolean {
  const expectedSources = expected.evidence?.sourceLocations ?? [];
  const actualSources = actual.sourceLocations ?? [];
  const lineTolerance = effectiveLineTolerance(expected, thresholds);
  return expectedSources.some((expectedSource) =>
    actualSources.some((actualSource) =>
      locationValuesMatch(expectedSource, actualSource, lineTolerance),
    ),
  );
}

function locationValuesMatch(
  expected: NonNullable<GroundTruthFinding["location"]>,
  actual: NonNullable<ActualFindingProjection["location"]>,
  lineTolerance: number,
): boolean {
  if (!pathMatches(expected.path, actual.path)) {
    return false;
  }
  const expectedRange = toLineRange(expected.startLine, expected.endLine);
  if (!expectedRange) {
    return true;
  }
  const actualRange = toLineRange(actual.startLine, actual.endLine);
  if (!actualRange) {
    return false;
  }
  return (
    rangesOverlap(expectedRange, actualRange) ||
    rangeDistance(expectedRange, actualRange) <= lineTolerance
  );
}

function effectiveLineTolerance(
  expected: GroundTruthFinding,
  thresholds: MatchThresholds,
): number {
  return (
    expected.matchHints?.lineTolerance ?? thresholds.defaultLineTolerance
  );
}

function rulesMatch(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): boolean {
  return ruleOverlap(expected, actual).length > 0;
}

function ruleOverlap(
  expected: GroundTruthFinding,
  actual: ActualFindingProjection,
): string[] {
  const expectedRules = normalizeIdentifierSet(
    [...(expected.ruleIds ?? []), ...(expected.aliases ?? [])],
    "rule",
  );
  const actualRules = normalizeIdentifierSet(actual.ruleIds, "rule");
  return actualRules.filter((rule) => expectedRules.includes(rule));
}

function compareCandidates(
  left: MatchCandidate,
  right: MatchCandidate,
): number {
  return (
    Number(right.eligible) - Number(left.eligible) ||
    right.evidenceScore - left.evidenceScore ||
    left.expectedId.localeCompare(right.expectedId) ||
    left.actualFingerprint.localeCompare(right.actualFingerprint) ||
    left.actualCategory.localeCompare(right.actualCategory) ||
    (left.actualPath ?? "").localeCompare(right.actualPath ?? "")
  );
}

function compareActualForAssignment(
  left: ActualFindingProjection,
  right: ActualFindingProjection,
): number {
  return (
    left.fingerprint.localeCompare(right.fingerprint) ||
    actualFindingNoiseKey(left).localeCompare(actualFindingNoiseKey(right)) ||
    left.id.localeCompare(right.id)
  );
}

function toLineRange(
  startLine: number | undefined,
  endLine: number | undefined,
) {
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

function rangeDistance(
  left: { start: number; end: number },
  right: { start: number; end: number },
): number {
  if (rangesOverlap(left, right)) {
    return 0;
  }

  return left.end < right.start
    ? right.start - left.end
    : left.start - right.end;
}
