import { normalizeCwe } from "./identifierNormalize.js";
import type { CweToleranceMode } from "./schema.js";

const weaknessBuckets: Record<string, readonly number[]> = {
  injection: [77, 78, 79, 89, 90, 94, 95, 643, 943],
  "path-traversal": [22, 23, 36, 73],
  ssrf: [918],
  xxe: [611],
  deserialization: [502],
  "weak-crypto": [326, 327, 328, 330, 916],
  secrets: [259, 321, 798],
  "access-control": [284, 285, 287, 306, 862, 863],
  config: [16, 489, 614],
};

const cweToBucket = new Map<string, string>(
  Object.entries(weaknessBuckets).flatMap(([bucket, cwes]) =>
    cwes.map((cwe) => [`CWE-${cwe}`, bucket] as const),
  ),
);

export function normalizeCweList(values: readonly string[] | undefined): string[] {
  const normalized = new Set<string>();
  for (const value of values ?? []) {
    const cwe = normalizeCwe(value);
    if (cwe) {
      normalized.add(cwe);
    }
  }

  return [...normalized].sort();
}

export function cweBucket(cwe: string): string | undefined {
  const normalized = normalizeCwe(cwe);
  return normalized ? cweToBucket.get(normalized) : undefined;
}

export function cweIntersection(expected: readonly string[], actual: readonly string[]): string[] {
  const expectedSet = new Set(normalizeCweList(expected));
  return normalizeCweList(actual).filter((value) => expectedSet.has(value));
}

export function cweAliasIntersection(
  expected: readonly string[],
  actual: readonly string[],
  aliases: readonly string[],
): string[] {
  const expectedAndAliases = new Set([...normalizeCweList(expected), ...normalizeCweList(aliases)]);
  return normalizeCweList(actual).filter((value) => expectedAndAliases.has(value));
}

export function cweFamilyIntersection(expected: readonly string[], actual: readonly string[]): string[] {
  const expectedBuckets = new Set(normalizeCweList(expected).map(cweBucket).filter(isString));
  return normalizeCweList(actual).filter((value) => {
    const bucket = cweBucket(value);
    return bucket ? expectedBuckets.has(bucket) : false;
  });
}

export function scoreCweMatch(
  expected: readonly string[],
  actual: readonly string[],
  aliases: readonly string[],
  tolerance: CweToleranceMode,
): { points: number; explanation: string } {
  const exact = cweIntersection(expected, actual);
  if (exact.length > 0) {
    return { points: 25, explanation: `CWE matches exactly: ${exact.join(", ")}` };
  }

  if (tolerance === "exact") {
    return { points: 0, explanation: "no exact CWE overlap" };
  }

  const alias = cweAliasIntersection(expected, actual, aliases);
  if (alias.length > 0) {
    return { points: 15, explanation: `CWE matches an alias: ${alias.join(", ")}` };
  }

  if (tolerance !== "weakness-family") {
    return { points: 0, explanation: "no CWE alias overlap" };
  }

  const family = cweFamilyIntersection(expected, actual);
  if (family.length > 0) {
    return { points: 15, explanation: `CWE is in the same weakness family: ${family.join(", ")}` };
  }

  return { points: 0, explanation: "no tolerated CWE family overlap" };
}

function isString(value: string | undefined): value is string {
  return typeof value === "string";
}
