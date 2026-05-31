import type { DetectionCounts, EvalSeverity, MatchResult } from "./schema.js";

export type Matrix = Record<string, Record<string, number>>;

export function detectionCounts(matchResult: MatchResult): DetectionCounts {
  return {
    truePositive: matchResult.matches.length,
    falsePositive: matchResult.falsePositives.length,
    falseNegative: matchResult.falseNegatives.length,
    trueNegative: matchResult.trueNegative ? 1 : 0,
  };
}

export function categoryMatrix(matchResult: MatchResult): Matrix {
  const matrix: Matrix = {};
  for (const match of matchResult.matches) {
    increment(matrix, match.expectedCategory, match.actualCategory);
  }

  for (const finding of matchResult.falseNegatives) {
    increment(matrix, finding.category, "<missed>");
  }

  for (const finding of matchResult.falsePositives) {
    increment(matrix, "<spurious>", finding.category);
  }

  return matrix;
}

export function severityMatrix(
  matchResult: MatchResult,
  expectedSeverityById: ReadonlyMap<string, EvalSeverity>,
  actualSeverityByFingerprint: ReadonlyMap<string, EvalSeverity>,
): Matrix {
  const matrix: Matrix = {};
  for (const match of matchResult.matches) {
    const expectedSeverity = expectedSeverityById.get(match.expectedId);
    const actualSeverity = actualSeverityByFingerprint.get(match.actualFingerprint);
    if (expectedSeverity && actualSeverity) {
      increment(matrix, expectedSeverity, actualSeverity);
    }
  }

  for (const finding of matchResult.falseNegatives) {
    increment(matrix, finding.severity, "<missed>");
  }

  for (const finding of matchResult.falsePositives) {
    increment(matrix, "<spurious>", finding.severity);
  }

  return matrix;
}

export function increment(matrix: Matrix, row: string, column: string): void {
  matrix[row] ??= {};
  matrix[row][column] = (matrix[row][column] ?? 0) + 1;
}
