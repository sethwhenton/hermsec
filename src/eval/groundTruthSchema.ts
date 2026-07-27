import path from "node:path";
import { normalizeCweList } from "./cweTolerance.js";
import { normalizeIdentifiers, normalizeIdentifierSet } from "./identifierNormalize.js";
import { normalizeEvalPath } from "./pathNormalize.js";
import type {
  EvalFindingCategory,
  EvalLocation,
  EvalSeverity,
  FixtureManifestV2,
  GroundTruthEvidence,
  GroundTruthEvidenceType,
  GroundTruthFinding,
  GroundTruthMatchHints,
  GroundTruthMatchPolicy,
  TruthSetV2,
} from "./schema.js";
import { normalizeVulnerabilityClass } from "./vulnerabilityClass.js";

const categories = new Set<EvalFindingCategory>([
  "code",
  "dependency",
  "secret",
  "supply-chain",
  "config",
]);
const severities = new Set<EvalSeverity>([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);
const evidenceTypes = new Set<GroundTruthEvidenceType>([
  "primary-location",
  "source-and-sink",
  "secret-location",
  "package-advisory",
]);

export function normalizeGroundTruthFinding(
  input: GroundTruthFinding,
  fixtureRoot?: string,
): GroundTruthFinding {
  const location = input.location
    ? normalizeLocation(input.location, fixtureRoot)
    : undefined;
  const evidence = input.evidence
    ? {
        ...input.evidence,
        ...(input.evidence.sourceLocations
          ? {
              sourceLocations: input.evidence.sourceLocations.map((source) =>
                normalizeLocation(source, fixtureRoot),
              ),
            }
          : {}),
      }
    : undefined;

  return {
    id: input.id,
    category: input.category,
    ...(input.vulnerabilityClass
      ? {
          vulnerabilityClass: normalizeVulnerabilityClass(
            input.vulnerabilityClass,
          ),
        }
      : {}),
    title: input.title,
    severity: input.severity,
    cwe: normalizeCweList(input.cwe),
    identifiers: normalizeIdentifiers(input.identifiers),
    ...(location ? { location } : {}),
    ...(evidence ? { evidence } : {}),
    ...(input.matchPolicy ? { matchPolicy: { ...input.matchPolicy } } : {}),
    ...(input.package ? { package: { ...input.package } } : {}),
    ...(input.ruleIds
      ? { ruleIds: normalizeIdentifierSet(input.ruleIds, "rule") }
      : {}),
    ...(input.aliases ? { aliases: [...input.aliases].sort() } : {}),
    ...(input.tags ? { tags: [...input.tags].sort() } : {}),
    ...(input.matchHints ? { matchHints: { ...input.matchHints } } : {}),
  };
}

export function validateGroundTruthFinding(
  input: unknown,
  options: { fixtureRoot?: string; requireV2?: boolean } = {},
): GroundTruthFinding {
  if (!isRecord(input)) {
    throw new Error("ground truth finding must be an object");
  }

  const id = requireString(input, "id");
  const category = requireEnum(input, "category", categories, "category");
  const vulnerabilityClass = optionalString(input, "vulnerabilityClass");
  const title = requireString(input, "title");
  const severity = requireEnum(input, "severity", severities, "severity");
  const cwe = optionalStringArray(input, "cwe");
  const identifiers = readIdentifiers(input.identifiers);
  const location = readLocation(input.location);
  const evidence = readEvidence(input.evidence);
  const packageRef = readPackage(input.package);
  const matchHints = readMatchHints(input.matchHints);
  const matchPolicy = readMatchPolicy(input.matchPolicy);

  if (options.requireV2) {
    if (!vulnerabilityClass) {
      throw new Error(
        `ground truth ${id} vulnerabilityClass is required by schema 2.0`,
      );
    }
    if (!evidence) {
      throw new Error(`ground truth ${id} evidence is required by schema 2.0`);
    }
    if (!matchPolicy) {
      throw new Error(
        `ground truth ${id} matchPolicy is required by schema 2.0`,
      );
    }
    validateV2EvidenceContract({
      id,
      category,
      location,
      evidence,
      packageRef,
      identifiers,
      matchPolicy,
      matchHints,
    });
    if (location) {
      assertRelativeFixturePath(location.path, `ground truth ${id} location`);
    }
    for (const source of evidence?.sourceLocations ?? []) {
      assertRelativeFixturePath(
        source.path,
        `ground truth ${id} source location`,
      );
    }
  }

  return normalizeGroundTruthFinding(
    {
      id,
      category,
      ...(vulnerabilityClass ? { vulnerabilityClass } : {}),
      title,
      severity,
      cwe,
      identifiers,
      ...(location ? { location } : {}),
      ...(evidence ? { evidence } : {}),
      ...(matchPolicy ? { matchPolicy } : {}),
      ...(packageRef ? { package: packageRef } : {}),
      ...(optionalStringArray(input, "ruleIds").length > 0
        ? { ruleIds: optionalStringArray(input, "ruleIds") }
        : {}),
      ...(optionalStringArray(input, "aliases").length > 0
        ? { aliases: optionalStringArray(input, "aliases") }
        : {}),
      ...(optionalStringArray(input, "tags").length > 0
        ? { tags: optionalStringArray(input, "tags") }
        : {}),
      ...(matchHints ? { matchHints } : {}),
    },
    options.fixtureRoot,
  );
}

export function validateTruthSetV2(
  input: unknown,
  fixtureRoot?: string,
): TruthSetV2 {
  if (!isRecord(input) || input.schemaVersion !== "2.0") {
    throw new Error("truth set schemaVersion must be 2.0");
  }

  const fixtureId = requireString(input, "fixtureId");
  if (!Array.isArray(input.findings)) {
    throw new Error("truth set findings must be an array");
  }

  const findings = input.findings.map((finding) =>
    validateGroundTruthFinding(finding, {
      ...(fixtureRoot ? { fixtureRoot } : {}),
      requireV2: true,
    }),
  );
  assertUnique(findings.map((finding) => finding.id), "ground truth finding id");

  return {
    schemaVersion: "2.0",
    fixtureId,
    findings,
  };
}

export function parseGroundTruthDocument(
  input: unknown,
  fixtureRoot?: string,
): GroundTruthFinding[] {
  if (Array.isArray(input)) {
    return input.map((finding) =>
      validateGroundTruthFinding(finding, {
        ...(fixtureRoot ? { fixtureRoot } : {}),
      }),
    );
  }

  return validateTruthSetV2(input, fixtureRoot).findings;
}

export function validateFixtureManifestV2(input: unknown): FixtureManifestV2 {
  if (!isRecord(input) || input.schemaVersion !== "2.0") {
    throw new Error("fixture manifest schemaVersion must be 2.0");
  }

  const variant = input.variant;
  if (variant !== "vulnerable" && variant !== "clean") {
    throw new Error("fixture manifest variant must be vulnerable or clean");
  }

  const expectedFindingCount = input.expectedFindingCount;
  if (
    !Number.isSafeInteger(expectedFindingCount) ||
    (expectedFindingCount as number) < 0
  ) {
    throw new Error(
      "fixture manifest expectedFindingCount must be a non-negative integer",
    );
  }

  const safety = input.safety;
  if (
    !isRecord(safety) ||
    safety.networkRequired !== false ||
    safety.executionRequired !== false ||
    safety.containsRealSecrets !== false ||
    safety.executionPolicy !== "never" ||
    safety.networkPolicy !== "deny"
  ) {
    throw new Error(
      "fixture manifest safety must deny execution and network access and forbid real secrets",
    );
  }

  const manifest: FixtureManifestV2 = {
    schemaVersion: "2.0",
    id: requireString(input, "id"),
    pairId: requireString(input, "pairId"),
    variant,
    language: requireString(input, "language"),
    projectRoot: requireString(input, "projectRoot") as "project",
    evaluatorFiles: requiredStringArray(input, "evaluatorFiles"),
    entrypoints: requiredStringArray(input, "entrypoints"),
    sourceFiles: requiredStringArray(input, "sourceFiles"),
    supportedVulnerabilityClasses: requiredStringArray(
      input,
      "supportedVulnerabilityClasses",
    ).map(normalizeVulnerabilityClass),
    expectedFindingCount: expectedFindingCount as number,
    pairedFixtureId: requireString(input, "pairedFixtureId"),
    safety: {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
  };

  assertUnique(manifest.entrypoints, "fixture entrypoint");
  assertUnique(manifest.sourceFiles, "fixture source file");
  assertUnique(manifest.evaluatorFiles, "fixture evaluator file");
  assertUnique(
    manifest.supportedVulnerabilityClasses,
    "fixture vulnerability class",
  );
  if (
    manifest.variant === "clean" &&
    manifest.expectedFindingCount !== 0
  ) {
    throw new Error("clean fixture expectedFindingCount must be zero");
  }
  for (const entrypoint of manifest.entrypoints) {
    assertRelativeFixturePath(entrypoint, "fixture entrypoint");
    assertCanonicalManifestPath(entrypoint, "fixture entrypoint");
  }
  for (const sourceFile of manifest.sourceFiles) {
    assertRelativeFixturePath(sourceFile, "fixture source file");
    assertCanonicalManifestPath(sourceFile, "fixture source file");
  }
  if (manifest.projectRoot !== "project") {
    throw new Error("fixture manifest projectRoot must be project");
  }
  for (const evaluatorFile of manifest.evaluatorFiles) {
    assertRelativeFixturePath(
      evaluatorFile,
      "fixture evaluator file",
    );
    assertCanonicalManifestPath(
      evaluatorFile,
      "fixture evaluator file",
    );
    if (
      evaluatorFile.includes("/") ||
      evaluatorFile.includes("\\") ||
      evaluatorFile === manifest.projectRoot
    ) {
      throw new Error(
        "fixture evaluatorFiles must name root-level files outside project/",
      );
    }
  }
  if (
    manifest.evaluatorFiles.length === 0 ||
    !manifest.evaluatorFiles.includes("truth.json") ||
    manifest.evaluatorFiles.includes("fixture.json") ||
    [...manifest.evaluatorFiles].sort().join("\0") !==
      manifest.evaluatorFiles.join("\0")
  ) {
    throw new Error(
      "fixture manifest evaluatorFiles must be sorted, include truth.json, and omit fixture.json",
    );
  }
  assertNoCaseAliases(manifest.entrypoints, "fixture entrypoint");
  assertNoCaseAliases(manifest.sourceFiles, "fixture source file");
  assertNoCaseAliases(
    manifest.evaluatorFiles,
    "fixture evaluator file",
  );
  if (
    manifest.entrypoints.some(
      (entrypoint) => !manifest.sourceFiles.includes(entrypoint),
    )
  ) {
    throw new Error("fixture entrypoints must be included in sourceFiles");
  }

  return manifest;
}

function validateV2EvidenceContract(input: {
  id: string;
  category: EvalFindingCategory;
  location: EvalLocation | undefined;
  evidence: GroundTruthEvidence;
  packageRef: GroundTruthFinding["package"];
  identifiers: GroundTruthFinding["identifiers"];
  matchPolicy: GroundTruthMatchPolicy;
  matchHints: GroundTruthMatchHints | undefined;
}): void {
  if (input.matchPolicy.category !== "exact") {
    throw new Error(`ground truth ${input.id} category policy must be exact`);
  }
  if (input.matchPolicy.evidence !== input.evidence.type) {
    throw new Error(
      `ground truth ${input.id} evidence type must match matchPolicy`,
    );
  }

  if (input.evidence.type === "package-advisory") {
    if (input.category !== "dependency" || !input.packageRef) {
      throw new Error(
        `ground truth ${input.id} package-advisory evidence requires a dependency package`,
      );
    }
    const advisoryCount =
      input.identifiers.cve.length +
      input.identifiers.ghsa.length +
      input.identifiers.osv.length;
    if (advisoryCount === 0 && !input.matchHints?.advisoryMatchOptional) {
      throw new Error(
        `ground truth ${input.id} package-advisory evidence requires an advisory identifier`,
      );
    }
    return;
  }

  if (input.matchPolicy.location === "required" && !input.location) {
    throw new Error(`ground truth ${input.id} requires a primary location`);
  }
  if (
    input.matchPolicy.line === "required" &&
    typeof input.location?.startLine !== "number"
  ) {
    throw new Error(`ground truth ${input.id} requires a primary line`);
  }
  if (
    input.evidence.type === "source-and-sink" &&
    (input.evidence.sourceLocations?.length ?? 0) === 0
  ) {
    throw new Error(
      `ground truth ${input.id} source-and-sink evidence requires a source location`,
    );
  }
}

function normalizeLocation(
  location: EvalLocation,
  fixtureRoot?: string,
): EvalLocation {
  return {
    path: normalizeEvalPath(location.path, fixtureRoot),
    ...(typeof location.startLine === "number"
      ? { startLine: location.startLine }
      : {}),
    ...(typeof location.endLine === "number"
      ? { endLine: location.endLine }
      : {}),
  };
}

function requireString(input: Record<string, unknown>, key: string): string {
  const value = input[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`ground truth ${key} must be a non-empty string`);
  }

  return value;
}

function optionalString(
  input: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = input[key];
  if (value === undefined) {
    return undefined;
  }
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

function optionalStringArray(
  input: Record<string, unknown>,
  key: string,
): string[] {
  const value = input[key];
  if (value === undefined) {
    return [];
  }

  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new Error(`ground truth ${key} must be an array of strings`);
  }

  return value;
}

function requiredStringArray(
  input: Record<string, unknown>,
  key: string,
): string[] {
  const values = optionalStringArray(input, key);
  if (values.length === 0) {
    throw new Error(`ground truth ${key} must be a non-empty string array`);
  }
  if (values.some((value) => value.trim() === "")) {
    throw new Error(`ground truth ${key} cannot contain empty strings`);
  }
  return values;
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

function readLocation(value: unknown): EvalLocation | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("ground truth location must be an object");
  }

  const fileValue = value.file ?? value.path;
  if (typeof fileValue !== "string" || fileValue.trim() === "") {
    throw new Error(
      "ground truth location file/path must be a non-empty string",
    );
  }

  const startLine = value.startLine;
  const endLine = value.endLine;
  if (
    startLine !== undefined &&
    (!Number.isSafeInteger(startLine) || (startLine as number) <= 0)
  ) {
    throw new Error("ground truth location startLine must be a positive integer");
  }
  if (
    endLine !== undefined &&
    (!Number.isSafeInteger(endLine) || (endLine as number) <= 0)
  ) {
    throw new Error("ground truth location endLine must be a positive integer");
  }
  if (
    typeof startLine === "number" &&
    typeof endLine === "number" &&
    endLine < startLine
  ) {
    throw new Error("ground truth location endLine cannot precede startLine");
  }

  return {
    path: fileValue,
    ...(typeof startLine === "number" ? { startLine } : {}),
    ...(typeof endLine === "number" ? { endLine } : {}),
  };
}

function readEvidence(value: unknown): GroundTruthEvidence | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value) || !evidenceTypes.has(value.type as GroundTruthEvidenceType)) {
    throw new Error("ground truth evidence type is invalid");
  }

  const sourceLocations = value.sourceLocations;
  if (
    sourceLocations !== undefined &&
    (!Array.isArray(sourceLocations) ||
      sourceLocations.some((location) => !isRecord(location)))
  ) {
    throw new Error(
      "ground truth evidence sourceLocations must be an array of locations",
    );
  }

  const parsedSources = (sourceLocations ?? []).map((location) =>
    readLocation(location),
  );
  if (parsedSources.some((location) => location === undefined)) {
    throw new Error("ground truth evidence source location is invalid");
  }

  const description = value.description;
  if (description !== undefined && typeof description !== "string") {
    throw new Error("ground truth evidence description must be a string");
  }

  return {
    type: value.type as GroundTruthEvidenceType,
    ...(parsedSources.length > 0
      ? { sourceLocations: parsedSources as EvalLocation[] }
      : {}),
    ...(typeof description === "string" ? { description } : {}),
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

function readMatchHints(
  value: unknown,
): GroundTruthMatchHints | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error("ground truth matchHints must be an object");
  }
  if (
    value.lineTolerance !== undefined &&
    (!Number.isSafeInteger(value.lineTolerance) ||
      (value.lineTolerance as number) < 0)
  ) {
    throw new Error(
      "ground truth matchHints lineTolerance must be a non-negative integer",
    );
  }
  if (
    value.severityTolerance !== undefined &&
    value.severityTolerance !== "exact" &&
    value.severityTolerance !== "one-step" &&
    value.severityTolerance !== "category-only"
  ) {
    throw new Error("ground truth matchHints severityTolerance is invalid");
  }
  if (
    value.cweTolerance !== undefined &&
    value.cweTolerance !== "exact" &&
    value.cweTolerance !== "alias" &&
    value.cweTolerance !== "weakness-family"
  ) {
    throw new Error("ground truth matchHints cweTolerance is invalid");
  }
  if (
    value.advisoryMatchOptional !== undefined &&
    typeof value.advisoryMatchOptional !== "boolean"
  ) {
    throw new Error(
      "ground truth matchHints advisoryMatchOptional must be boolean",
    );
  }

  return {
    ...(typeof value.lineTolerance === "number"
      ? { lineTolerance: value.lineTolerance }
      : {}),
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

function readMatchPolicy(
  value: unknown,
): GroundTruthMatchPolicy | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new Error("ground truth matchPolicy must be an object");
  }
  if (
    value.category !== "exact" ||
    (value.vulnerabilityClass !== "exact" &&
      value.vulnerabilityClass !== "compatible") ||
    (value.location !== "required" && value.location !== "optional") ||
    (value.line !== "required" && value.line !== "optional") ||
    !evidenceTypes.has(value.evidence as GroundTruthEvidenceType)
  ) {
    throw new Error("ground truth matchPolicy is invalid");
  }

  return {
    category: "exact",
    vulnerabilityClass: value.vulnerabilityClass,
    location: value.location,
    line: value.line,
    evidence: value.evidence as GroundTruthEvidenceType,
  };
}

function assertUnique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      throw new Error(`${label} must be unique: ${value}`);
    }
    seen.add(value);
  }
}

function assertRelativeFixturePath(value: string, label: string): void {
  const normalized = value.replace(/\\/g, "/");
  if (
    normalized.startsWith("/") ||
    /^[a-z]:\//i.test(normalized) ||
    normalized.split("/").includes("..")
  ) {
    throw new Error(`${label} must be repository-relative`);
  }
}

function assertCanonicalManifestPath(value: string, label: string): void {
  if (
    value.includes("\\") ||
    value.includes("\0") ||
    path.posix.normalize(value) !== value ||
    value === "." ||
    value.endsWith("/")
  ) {
    throw new Error(`${label} must be a canonical relative path`);
  }
}

function assertNoCaseAliases(
  values: readonly string[],
  label: string,
): void {
  if (new Set(values.map((value) => value.toLowerCase())).size !== values.length) {
    throw new Error(`${label} cannot contain case-folded path aliases`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
