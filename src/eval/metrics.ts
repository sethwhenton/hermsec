import type { Finding, FindingCategory, Severity } from "../shared/types.js";
import { projectFindings } from "./findingProjection.js";
import { normalizeGroundTruthFinding } from "./groundTruthSchema.js";
import { matchFindings } from "./matcher.js";
import type { DetectionCounts, EvalMetrics, GroundTruthFinding, MatchResult } from "./schema.js";

export type { EvalMetrics, GroundTruthFinding } from "./schema.js";

export type SimpleGroundTruthFinding = {
  id: string;
  category: FindingCategory;
  severity: Severity;
  cwe?: string[];
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  location?: {
    file: string;
    startLine?: number;
    endLine?: number;
  };
  package?: {
    ecosystem: string;
    name: string;
    installedVersion?: string;
  };
};

export type SimpleMatchResult = {
  expectedId: string;
  findingId: string;
  score: number;
};

export type SimpleEvalMetrics = {
  totalExpected: number;
  totalActual: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  precision: number;
  recall: number;
  f1: number;
  matches: SimpleMatchResult[];
  unmatchedExpected: string[];
  unmatchedActual: string[];
};

export function computeMetricsFromCounts(
  counts: DetectionCounts,
  totalExpected = counts.truePositive + counts.falseNegative,
  totalActual = counts.truePositive + counts.falsePositive,
): EvalMetrics {
  const precision = safeRatio(counts.truePositive, counts.truePositive + counts.falsePositive, 1);
  const recall = safeRatio(counts.truePositive, counts.truePositive + counts.falseNegative, 1);
  const f1 = fScore(precision, recall);

  return {
    totalExpected,
    totalActual,
    truePositive: counts.truePositive,
    falsePositive: counts.falsePositive,
    falseNegative: counts.falseNegative,
    trueNegativeCases: counts.trueNegative,
    precision,
    recall,
    f1,
    falsePositiveRate: safeRatio(
      counts.falsePositive,
      counts.falsePositive + counts.trueNegative,
      counts.falsePositive > 0 ? 1 : 0,
    ),
    falseNegativeRate: safeRatio(counts.falseNegative, counts.falseNegative + counts.truePositive, 0),
    macroF1: f1,
    weightedF1: f1,
  };
}

export function computeMetrics(matchResult: MatchResult): EvalMetrics {
  return computeMetricsFromCounts(
    {
      truePositive: matchResult.matches.length,
      falsePositive: matchResult.falsePositives.length,
      falseNegative: matchResult.falseNegatives.length,
      trueNegative: matchResult.trueNegative ? 1 : 0,
    },
    matchResult.matches.length + matchResult.falseNegatives.length,
    matchResult.matches.length + matchResult.falsePositives.length,
  );
}

export function evaluateFindings(
  expected: readonly (GroundTruthFinding | SimpleGroundTruthFinding)[],
  actual: readonly Finding[],
): EvalMetrics {
  const normalizedExpected = expected.map((finding) => normalizeGroundTruthFinding(toGroundTruthFinding(finding)));
  const projectedActual = projectFindings(actual);
  return computeMetrics(matchFindings(normalizedExpected, projectedActual));
}

export function evaluateFindingsSimple(
  expected: readonly SimpleGroundTruthFinding[],
  actual: readonly Finding[],
  minScore = 60,
): SimpleEvalMetrics {
  const candidates: SimpleMatchResult[] = [];
  for (const truth of expected) {
    for (const finding of actual) {
      const score = scoreMatch(truth, finding);
      if (score >= minScore) {
        candidates.push({ expectedId: truth.id, findingId: finding.id, score });
      }
    }
  }

  const matches: SimpleMatchResult[] = [];
  const usedExpected = new Set<string>();
  const usedActual = new Set<string>();
  for (const candidate of candidates.sort(
    (left, right) =>
      right.score - left.score ||
      left.expectedId.localeCompare(right.expectedId) ||
      left.findingId.localeCompare(right.findingId),
  )) {
    if (!usedExpected.has(candidate.expectedId) && !usedActual.has(candidate.findingId)) {
      matches.push(candidate);
      usedExpected.add(candidate.expectedId);
      usedActual.add(candidate.findingId);
    }
  }

  const truePositive = matches.length;
  const falsePositive = actual.length - truePositive;
  const falseNegative = expected.length - truePositive;
  const precision = safeRatio(truePositive, truePositive + falsePositive, 1);
  const recall = safeRatio(truePositive, truePositive + falseNegative, 1);

  return {
    totalExpected: expected.length,
    totalActual: actual.length,
    truePositive,
    falsePositive,
    falseNegative,
    precision,
    recall,
    f1: fScore(precision, recall),
    matches,
    unmatchedExpected: expected.filter((item) => !usedExpected.has(item.id)).map((item) => item.id),
    unmatchedActual: actual.filter((item) => !usedActual.has(item.id)).map((item) => item.id),
  };
}

export function scoreMatch(expected: SimpleGroundTruthFinding, actual: Finding): number {
  let score = 0;
  if (expected.category === actual.category) score += 20;
  if (expected.severity === actual.severity) score += 10;
  if (sameLocation(expected, actual)) score += 30;
  if (samePackage(expected, actual)) score += 30;
  if (overlap(expected.cwe, actual.cwe)) score += 25;
  if (overlapIds(expected.identifiers, actual.identifiers)) score += 45;
  return score;
}

export function fScore(precision: number, recall: number): number {
  if (precision + recall === 0) {
    return 0;
  }

  return (2 * precision * recall) / (precision + recall);
}

export function safeRatio(numerator: number, denominator: number, emptyValue: number): number {
  if (denominator === 0) {
    return emptyValue;
  }

  return numerator / denominator;
}

function toGroundTruthFinding(input: GroundTruthFinding | SimpleGroundTruthFinding): GroundTruthFinding {
  if ("title" in input && "identifiers" in input && Array.isArray(input.cwe)) {
    return input;
  }

  return {
    id: input.id,
    category: input.category,
    title: input.id,
    severity: input.severity,
    cwe: input.cwe ?? [],
    identifiers: {
      cve: input.identifiers?.cve ?? [],
      ghsa: input.identifiers?.ghsa ?? [],
      osv: input.identifiers?.osv ?? [],
    },
    ...(input.location
      ? {
          location: {
            path: "path" in input.location ? input.location.path : input.location.file,
            ...(typeof input.location.startLine === "number" ? { startLine: input.location.startLine } : {}),
            ...(typeof input.location.endLine === "number" ? { endLine: input.location.endLine } : {}),
          },
        }
      : {}),
    ...(input.package ? { package: { ...input.package } } : {}),
  };
}

function sameLocation(expected: SimpleGroundTruthFinding, actual: Finding): boolean {
  if (!expected.location || !actual.location) return false;
  if (normalizePath(expected.location.file) !== normalizePath(actual.location.file)) return false;
  if (!expected.location.startLine || !actual.location.startLine) return true;
  return Math.abs(expected.location.startLine - actual.location.startLine) <= 3;
}

function samePackage(expected: SimpleGroundTruthFinding, actual: Finding): boolean {
  if (!expected.package || !actual.package) return false;
  return (
    expected.package.ecosystem.toLowerCase() === actual.package.ecosystem.toLowerCase() &&
    expected.package.name.toLowerCase() === actual.package.name.toLowerCase()
  );
}

function overlap(left?: readonly string[], right?: readonly string[]): boolean {
  if (!left?.length || !right?.length) return false;
  const normalized = new Set(right.map((item) => item.toUpperCase()));
  return left.some((item) => normalized.has(item.toUpperCase()));
}

function overlapIds(left?: SimpleGroundTruthFinding["identifiers"], right?: Finding["identifiers"]): boolean {
  return overlap(left?.cve, right?.cve) || overlap(left?.ghsa, right?.ghsa) || overlap(left?.osv, right?.osv);
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").toLowerCase();
}
