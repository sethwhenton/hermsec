import type { EvalSeverity, SeverityToleranceMode } from "./schema.js";

const severityRank: Record<EvalSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityDistance(expected: EvalSeverity, actual: EvalSeverity): number {
  return Math.abs(severityRank[expected] - severityRank[actual]);
}

export function severityMatches(
  expected: EvalSeverity,
  actual: EvalSeverity,
  tolerance: SeverityToleranceMode,
): boolean {
  if (tolerance === "category-only") {
    return true;
  }

  const distance = severityDistance(expected, actual);
  return tolerance === "exact" ? distance === 0 : distance <= 1;
}

export function scoreSeverity(
  expected: EvalSeverity,
  actual: EvalSeverity,
  tolerance: SeverityToleranceMode,
): { points: number; explanation: string } {
  if (expected === actual) {
    return { points: 10, explanation: "severity matches exactly" };
  }

  if (severityMatches(expected, actual, tolerance)) {
    return { points: 5, explanation: "severity is within configured tolerance" };
  }

  return { points: 0, explanation: "severity is outside configured tolerance" };
}
