import type { EvalIdentifiers } from "./schema.js";

export type IdentifierKind = "cve" | "ghsa" | "osv" | "cwe" | "rule";

export function normalizeCve(value: string): string | undefined {
  const match = value.trim().match(/cve[-_\s:]*(\d{4})[-_\s:]*(\d{4,})/i);
  if (!match) {
    return undefined;
  }

  const year = match[1];
  const number = match[2];
  if (!year || !number) {
    return undefined;
  }

  return `CVE-${year}-${number}`;
}

export function normalizeGhsa(value: string): string | undefined {
  const match = value
    .trim()
    .match(/ghsa[-_\s:]*([a-z0-9]{4})[-_\s]*([a-z0-9]{4})[-_\s]*([a-z0-9]{4})/i);
  if (!match) {
    return undefined;
  }

  const first = match[1];
  const second = match[2];
  const third = match[3];
  if (!first || !second || !third) {
    return undefined;
  }

  return `GHSA-${first}-${second}-${third}`.toUpperCase();
}

export function normalizeOsv(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  return trimmed.replace(/[_\s:]+/g, "-").toUpperCase();
}

export function normalizeCwe(value: string): string | undefined {
  const match = value.trim().match(/cwe[-_\s:]*(\d+)/i);
  if (!match?.[1]) {
    return undefined;
  }

  const numeric = Number.parseInt(match[1], 10);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return undefined;
  }

  return `CWE-${numeric}`;
}

export function normalizeRuleId(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  return trimmed.toLowerCase();
}

export function normalizeIdentifier(value: string, kind: IdentifierKind): string | undefined {
  switch (kind) {
    case "cve":
      return normalizeCve(value);
    case "ghsa":
      return normalizeGhsa(value);
    case "osv":
      return normalizeOsv(value);
    case "cwe":
      return normalizeCwe(value);
    case "rule":
      return normalizeRuleId(value);
  }
}

export function normalizeIdentifierSet(values: readonly string[] | undefined, kind: IdentifierKind): string[] {
  const normalized = new Set<string>();
  for (const value of values ?? []) {
    const item = normalizeIdentifier(value, kind);
    if (item) {
      normalized.add(item);
    }
  }

  return [...normalized].sort();
}

export function normalizeIdentifiers(input: Partial<EvalIdentifiers> | undefined): EvalIdentifiers {
  return {
    cve: normalizeIdentifierSet(input?.cve, "cve"),
    ghsa: normalizeIdentifierSet(input?.ghsa, "ghsa"),
    osv: normalizeIdentifierSet(input?.osv, "osv"),
  };
}

export function identifierOverlap(
  expected: EvalIdentifiers,
  actual: EvalIdentifiers,
  aliases: readonly string[] = [],
): string[] {
  const expectedValues = new Set([
    ...expected.cve,
    ...expected.ghsa,
    ...expected.osv,
    ...normalizeIdentifierSet(aliases, "cve"),
    ...normalizeIdentifierSet(aliases, "ghsa"),
    ...normalizeIdentifierSet(aliases, "osv"),
  ]);
  const actualValues = [...actual.cve, ...actual.ghsa, ...actual.osv];

  return actualValues.filter((value) => expectedValues.has(value)).sort();
}
