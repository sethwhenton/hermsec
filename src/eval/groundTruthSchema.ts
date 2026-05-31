import { normalizeCweList } from "./cweTolerance.js";
import { normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { normalizeEvalPath } from "./pathNormalize.js";
import type {
  EvalFindingCategory,
  EvalSeverity,
  GroundTruthFinding,
  GroundTruthMatchHints,
} from "./schema.js";

const categories = new Set<EvalFindingCategory>(["code", "dependency", "secret", "supply-chain", "config"]);
const severities = new Set<EvalSeverity>(["critical", "high", "medium", "low", "info"]);

export function normalizeGroundTruthFinding(input: GroundTruthFinding, fixtureRoot?: string): GroundTruthFinding {
  const location = input.location
    ? {
        path: normalizeEvalPath(input.location.path, fixtureRoot),
        ...(typeof input.location.startLine === "number" ? { startLine: input.location.startLine } : {}),
        ...(typeof input.location.endLine === "number" ? { endLine: input.location.endLine } : {}),
      }
    : undefined;

  return {
    id: input.id,
    category: input.category,
    title: input.title,
    severity: input.severity,
    cwe: normalizeCweList(input.cwe),
    identifiers: normalizeIdentifiers(input.identifiers),
    ...(location ? { location } : {}),
    ...(input.package ? { package: { ...input.package } } : {}),
    ...(input.ruleIds ? { ruleIds: normalizeIdentifierSet(input.ruleIds, "rule") } : {}),
    ...(input.aliases ? { aliases: [...input.aliases].sort() } : {}),
    ...(input.tags ? { tags: [...input.tags].sort() } : {}),
    ...(input.matchHints ? { matchHints: { ...input.matchHints } } : {}),
  };
}

export function validateGroundTruthFinding(input: unknown): GroundTruthFinding {
  if (!isRecord(input)) {
    throw new Error("ground truth finding must be an object");
  }

  const id = requireString(input, "id");
  const category = requireEnum(input, "category", categories, "category");
  const title = requireString(input, "title");
  const severity = requireEnum(input, "severity", severities, "severity");
  const cwe = optionalStringArray(input, "cwe");
  const identifiers = readIdentifiers(input.identifiers);
  const location = readLocation(input.location);
  const packageRef = readPackage(input.package);
  const matchHints = readMatchHints(input.matchHints);

  return normalizeGroundTruthFinding({
    id,
    category,
    title,
    severity,
    cwe,
    identifiers,
    ...(location ? { location } : {}),
    ...(packageRef ? { package: packageRef } : {}),
    ...(optionalStringArray(input, "ruleIds").length > 0 ? { ruleIds: optionalStringArray(input, "ruleIds") } : {}),
    ...(optionalStringArray(input, "aliases").length > 0 ? { aliases: optionalStringArray(input, "aliases") } : {}),
    ...(optionalStringArray(input, "tags").length > 0 ? { tags: optionalStringArray(input, "tags") } : {}),
    ...(matchHints ? { matchHints } : {}),
  });
}

function requireString(input: Record<string, unknown>, key: string): string {
  const value = input[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`ground truth ${key} must be a non-empty string`);
  }

  return value;
}

function requireEnum<T extends string>(
  input: Record<string, unknown>,
  key: string,
  allowed: ReadonlySet<T>,
  label: string,
): T {
  const value = input[key];
  if (typeof value !== "string" || !allowed.has(value as T)) {
    throw new Error(`ground truth ${label} is invalid`);
  }

  return value as T;
}

function optionalStringArray(input: Record<string, unknown>, key: string): string[] {
  const value = input[key];
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`ground truth ${key} must be an array of strings`);
  }

  return value;
}

function readIdentifiers(value: unknown) {
  if (value === undefined) {
    return { cve: [], ghsa: [], osv: [] };
  }

  if (!isRecord(value)) {
    throw new Error("ground truth identifiers must be an object");
  }

  return {
    cve: optionalStringArray(value, "cve"),
    ghsa: optionalStringArray(value, "ghsa"),
    osv: optionalStringArray(value, "osv"),
  };
}

function readLocation(value: unknown) {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("ground truth location must be an object");
  }

  const fileValue = value.file ?? value.path;
  if (typeof fileValue !== "string" || fileValue.trim() === "") {
    throw new Error("ground truth location file/path must be a non-empty string");
  }

  return {
    path: fileValue,
    ...(typeof value.startLine === "number" ? { startLine: value.startLine } : {}),
    ...(typeof value.endLine === "number" ? { endLine: value.endLine } : {}),
  };
}

function readPackage(value: unknown) {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("ground truth package must be an object");
  }

  const ecosystem = requireString(value, "ecosystem");
  const name = requireString(value, "name");
  const installedVersion = value.installedVersion;
  if (installedVersion !== undefined && typeof installedVersion !== "string") {
    throw new Error("ground truth package installedVersion must be a string");
  }

  return {
    ecosystem,
    name,
    ...(typeof installedVersion === "string" ? { installedVersion } : {}),
  };
}

function readMatchHints(value: unknown): GroundTruthMatchHints | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("ground truth matchHints must be an object");
  }

  return {
    ...(typeof value.lineTolerance === "number" ? { lineTolerance: value.lineTolerance } : {}),
    ...(value.severityTolerance === "exact" ||
    value.severityTolerance === "one-step" ||
    value.severityTolerance === "category-only"
      ? { severityTolerance: value.severityTolerance }
      : {}),
    ...(value.cweTolerance === "exact" ||
    value.cweTolerance === "alias" ||
    value.cweTolerance === "weakness-family"
      ? { cweTolerance: value.cweTolerance }
      : {}),
    ...(typeof value.advisoryMatchOptional === "boolean"
      ? { advisoryMatchOptional: value.advisoryMatchOptional }
      : {}),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
