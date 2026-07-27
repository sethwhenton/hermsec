import path from "node:path";
import { redactForLog } from "../agent/redaction.js";
import type { ResearchExecutionMode } from "./execution.js";
import {
  assertSafeArtifactPath,
  canonicalJson,
  prettyCanonicalJson,
  sha256,
  writeImmutableJson,
} from "./integrity.js";
import {
  MODEL_CALL_TRACE_FILE,
  MODEL_CALL_TRACE_ROLE_PLAN_VERSION,
  MODEL_CALL_TRACE_SCHEMA_VERSION,
  validateModelCallTrace,
  type ResearchModelCallTrace,
} from "./modelCallTrace.js";
import {
  hashStableConfinedFile,
  listStableTreeFiles,
  readStableConfinedFile,
} from "./stableFiles.js";

export type RunArtifactRecord = {
  path: string;
  bytes: number;
  sha256: string;
};

export type ResearchRunManifest = {
  schemaVersion: 2;
  runId: string;
  suite: string;
  mode: string;
  execution: ResearchExecutionMode;
  status: "success" | "partial" | "degraded" | "canceled" | "failed";
  startedAt: string;
  finishedAt: string;
  harnessVersion: string;
  promptVersion: string;
  sourceState: Readonly<Record<string, unknown>>;
  limits: Readonly<Record<string, unknown>>;
  models: readonly Readonly<Record<string, unknown>>[];
  metadata: Readonly<Record<string, unknown>>;
  redactionMarkers: readonly string[];
  artifacts: readonly RunArtifactRecord[];
  integrity: ResearchIntegrityNotice;
  manifestSha256: string;
};

export type ResearchIntegrityNotice = {
  kind: "sha256-tamper-evident";
  authenticated: false;
  notice: string;
};

export type CreateRunManifestInput = Omit<
  ResearchRunManifest,
  | "schemaVersion"
  | "artifacts"
  | "manifestSha256"
  | "redactionMarkers"
  | "integrity"
> & {
  artifactPaths: readonly string[];
};

export type RunIntegrityResult = {
  valid: boolean;
  manifest?: ResearchRunManifest;
  errors: readonly string[];
};

export const RUN_MANIFEST_FILE = "run-manifest.json";
export const SUITE_INDEX_FILE = "suite-index.json";
export const RESEARCH_INTEGRITY_NOTICE = Object.freeze({
  kind: "sha256-tamper-evident" as const,
  authenticated: false as const,
  notice:
    "Hashes detect accidental changes and unsophisticated tampering only. They are not signed or authenticated; a writer with artifact access can recompute them.",
});

export type ResearchSuiteIndexEntry = {
  runId: string;
  path: string;
  manifestSha256: string;
};

export type ResearchSuiteIndexV2 = {
  schemaVersion: 2;
  suiteId: string;
  createdAt: string;
  runs: readonly ResearchSuiteIndexEntry[];
  integrity: ResearchIntegrityNotice;
  indexSha256: string;
};

export type ResearchSuiteTruthBinding = {
  fixtureId: string;
  pairId: string;
  variant: "vulnerable" | "clean";
  path: string;
  artifactSha256: string;
  fixtureDigestSha256: string;
  projectRoot?: "project";
  projectDigestSha256?: string;
  evaluatorDigestSha256?: string;
  layoutBindingSha256?: string;
};

export type ResearchSuiteIndexV3 = {
  schemaVersion: 3;
  suiteId: string;
  createdAt: string;
  runs: readonly ResearchSuiteIndexEntry[];
  artifacts: readonly RunArtifactRecord[];
  fixtureTruth: readonly ResearchSuiteTruthBinding[];
  integrity: ResearchIntegrityNotice;
  indexSha256: string;
};

export type ResearchSuiteIndex = ResearchSuiteIndexV2 | ResearchSuiteIndexV3;

export type CreateSuiteTruthBindingInput = Omit<
  ResearchSuiteTruthBinding,
  "artifactSha256"
>;

const REQUIRED_SUITE_ARTIFACTS = Object.freeze([
  "evaluation.json",
  "source-index.json",
  "experiment-summary.json",
  "cost-ledger.jsonl",
] as const);

const MAX_RESEARCH_ARTIFACT_BYTES = 256 * 1024 * 1024;
const RESEARCH_ARTIFACT_TREE_LIMITS = Object.freeze({
  maxDepth: 32,
  maxDirectories: 10_000,
  maxFiles: 50_000,
});

export async function createRunManifest(
  runDirectory: string,
  input: CreateRunManifestInput,
): Promise<ResearchRunManifest> {
  validateManifestInput(input);
  const normalizedPaths = input.artifactPaths.map(normalizeArtifactPath);
  const uniquePaths = [...new Set(normalizedPaths)].sort();
  if (uniquePaths.length !== input.artifactPaths.length) {
    throw new Error("Run manifests cannot contain duplicate artifact paths.");
  }
  if (uniquePaths.includes(RUN_MANIFEST_FILE)) {
    throw new Error("A run manifest cannot include itself as an artifact.");
  }

  const artifacts: RunArtifactRecord[] = [];
  for (const relativePath of uniquePaths) {
    assertSafeArtifactPath(runDirectory, relativePath);
    const integrity = await hashStableConfinedFile(
      runDirectory,
      relativePath,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    artifacts.push({
      path: normalizeArtifactPath(relativePath),
      bytes: integrity.bytes,
      sha256: integrity.sha256,
    });
  }

  const sanitized = redactForLog({
    sourceState: input.sourceState,
    limits: input.limits,
    models: input.models,
    metadata: input.metadata,
  });
  const sanitizedValue = sanitized.value as {
    sourceState: Readonly<Record<string, unknown>>;
    limits: Readonly<Record<string, unknown>>;
    models: readonly Readonly<Record<string, unknown>>[];
    metadata: Readonly<Record<string, unknown>>;
  };
  const unsigned = {
    schemaVersion: 2 as const,
    runId: input.runId,
    suite: input.suite,
    mode: input.mode,
    execution: input.execution,
    status: input.status,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    harnessVersion: input.harnessVersion,
    promptVersion: input.promptVersion,
    sourceState: sanitizedValue.sourceState,
    limits: sanitizedValue.limits,
    models: sanitizedValue.models,
    metadata: sanitizedValue.metadata,
    redactionMarkers: sanitized.markers,
    artifacts,
    integrity: RESEARCH_INTEGRITY_NOTICE,
  };
  const manifest: ResearchRunManifest = {
    ...unsigned,
    manifestSha256: sha256(canonicalJson(unsigned)),
  };
  await writeImmutableJson(path.join(path.resolve(runDirectory), RUN_MANIFEST_FILE), manifest);
  return manifest;
}

export async function createSuiteIndex(
  suiteDirectory: string,
  input: {
    suiteId: string;
    createdAt: string;
    runManifestPaths: readonly string[];
    artifactPaths?: readonly string[];
    fixtureTruth?: readonly CreateSuiteTruthBindingInput[];
  },
): Promise<ResearchSuiteIndex> {
  if (!input.suiteId.trim()) {
    throw new Error("Suite indexes require a non-empty suiteId.");
  }
  assertTimestamp(input.createdAt, "createdAt");
  const normalized = input.runManifestPaths.map(normalizeArtifactPath);
  const unique = [...new Set(normalized)].sort();
  if (unique.length !== normalized.length || unique.length === 0) {
    throw new Error(
      "Suite indexes require a non-empty set of unique run manifest paths.",
    );
  }

  const runs: ResearchSuiteIndexEntry[] = [];
  const runManifests: ResearchRunManifest[] = [];
  for (const relativePath of unique) {
    if (path.posix.basename(relativePath) !== RUN_MANIFEST_FILE) {
      throw new Error(`Suite index path is not a run manifest: ${relativePath}`);
    }
    const manifestPath = assertSafeArtifactPath(suiteDirectory, relativePath);
    await readStableConfinedFile(suiteDirectory, relativePath, {
      maxBytes: MAX_RESEARCH_ARTIFACT_BYTES,
    });
    const runDirectory = path.dirname(manifestPath);
    const validation = await validateRunArtifacts(runDirectory);
    if (!validation.valid || !validation.manifest) {
      throw new Error(
        `Suite index cannot include an invalid run manifest: ${relativePath}: ${validation.errors.join("; ")}`,
      );
    }
    runs.push({
      runId: validation.manifest.runId,
      path: relativePath,
      manifestSha256: validation.manifest.manifestSha256,
    });
    runManifests.push(validation.manifest);
  }

  const hasV3Artifacts = input.artifactPaths !== undefined;
  const hasV3Truth = input.fixtureTruth !== undefined;
  if (hasV3Artifacts !== hasV3Truth) {
    throw new Error(
      "Suite index v3 requires both artifactPaths and fixtureTruth bindings.",
    );
  }
  if (!hasV3Artifacts || !hasV3Truth) {
    const unsigned = {
      schemaVersion: 2 as const,
      suiteId: input.suiteId,
      createdAt: input.createdAt,
      runs,
      integrity: RESEARCH_INTEGRITY_NOTICE,
    };
    const index: ResearchSuiteIndexV2 = {
      ...unsigned,
      indexSha256: sha256(canonicalJson(unsigned)),
    };
    await writeImmutableJson(
      path.join(path.resolve(suiteDirectory), SUITE_INDEX_FILE),
      index,
    );
    return index;
  }

  const artifactPaths = input.artifactPaths;
  const fixtureTruthInput = input.fixtureTruth;
  if (!artifactPaths || !fixtureTruthInput) {
    throw new Error(
      "Suite index v3 artifact bindings disappeared during publication.",
    );
  }
  const normalizedArtifacts = artifactPaths.map(normalizeArtifactPath);
  const uniqueArtifacts = [...new Set(normalizedArtifacts)].sort();
  if (
    uniqueArtifacts.length !== normalizedArtifacts.length ||
    uniqueArtifacts.length === 0
  ) {
    throw new Error(
      "Suite index v3 requires a non-empty set of unique artifact paths.",
    );
  }
  if (uniqueArtifacts.includes(SUITE_INDEX_FILE)) {
    throw new Error("A suite index cannot include itself as an artifact.");
  }
  for (const required of REQUIRED_SUITE_ARTIFACTS) {
    if (!uniqueArtifacts.includes(required)) {
      throw new Error(
        `Suite index v3 is missing required artifact: ${required}`,
      );
    }
  }
  const runRoots = runs.map((run) => path.posix.dirname(run.path));
  for (const artifactPath of uniqueArtifacts) {
    if (
      runRoots.some(
        (runRoot) =>
          artifactPath === runRoot ||
          artifactPath.startsWith(`${runRoot}/`),
      )
    ) {
      throw new Error(
        `Suite-level artifact overlaps a run directory: ${artifactPath}`,
      );
    }
  }

  const artifacts: RunArtifactRecord[] = [];
  for (const relativePath of uniqueArtifacts) {
    assertSafeArtifactPath(suiteDirectory, relativePath);
    const integrity = await hashStableConfinedFile(
      suiteDirectory,
      relativePath,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    artifacts.push({
      path: relativePath,
      bytes: integrity.bytes,
      sha256: integrity.sha256,
    });
  }
  const artifactByPath = new Map(
    artifacts.map((artifact) => [artifact.path, artifact] as const),
  );
  const fixtureIds = new Set<string>();
  const truthPaths = new Set<string>();
  const fixtureTruth = fixtureTruthInput
    .map((binding): ResearchSuiteTruthBinding => {
      const relativePath = normalizeArtifactPath(binding.path);
      const structuralFields = [
        binding.projectRoot,
        binding.projectDigestSha256,
        binding.evaluatorDigestSha256,
        binding.layoutBindingSha256,
      ];
      const hasStructuralBinding = structuralFields.some(
        (value) => value !== undefined,
      );
      if (
        !binding.fixtureId.trim() ||
        !binding.pairId.trim() ||
        !["vulnerable", "clean"].includes(binding.variant) ||
        !/^[a-f0-9]{64}$/u.test(binding.fixtureDigestSha256) ||
        fixtureIds.has(binding.fixtureId) ||
        truthPaths.has(relativePath)
      ) {
        throw new Error(
          "Suite index v3 contains an invalid or duplicate fixture truth binding.",
        );
      }
      if (
        hasStructuralBinding &&
        (binding.projectRoot !== "project" ||
          !isSha256(binding.projectDigestSha256) ||
          !isSha256(binding.evaluatorDigestSha256) ||
          !isSha256(binding.layoutBindingSha256))
      ) {
        throw new Error(
          "Suite index v3 contains an incomplete structural fixture binding.",
        );
      }
      const artifact = artifactByPath.get(relativePath);
      if (!artifact) {
        throw new Error(
          `Fixture truth binding is not a listed suite artifact: ${relativePath}`,
        );
      }
      fixtureIds.add(binding.fixtureId);
      truthPaths.add(relativePath);
      return {
        fixtureId: binding.fixtureId,
        pairId: binding.pairId,
        variant: binding.variant,
        path: relativePath,
        artifactSha256: artifact.sha256,
        fixtureDigestSha256: binding.fixtureDigestSha256,
        ...(binding.projectRoot
          ? {
              projectRoot: binding.projectRoot,
              projectDigestSha256: binding.projectDigestSha256,
              evaluatorDigestSha256:
                binding.evaluatorDigestSha256,
              layoutBindingSha256: binding.layoutBindingSha256,
            }
          : {}),
      };
    })
    .sort((left, right) => left.fixtureId.localeCompare(right.fixtureId));
  if (fixtureTruth.length === 0) {
    throw new Error(
      "Suite index v3 requires at least one fixture truth binding.",
    );
  }
  for (const binding of fixtureTruth) {
    const truthErrors = await validateFixtureTruthArtifact(
      suiteDirectory,
      binding,
    );
    if (truthErrors.length > 0) {
      throw new Error(
        `Suite index cannot bind invalid fixture truth ${binding.path}: ${truthErrors.join("; ")}`,
      );
    }
  }
  for (const manifest of runManifests) {
    const bindingError = validateRunTruthBinding(
      manifest,
      fixtureTruth,
    );
    if (bindingError) {
      throw new Error(
        `Suite index cannot bind run ${manifest.runId}: ${bindingError}`,
      );
    }
  }
  const runFixtureIds = new Set(
    runManifests.map((manifest) =>
      isPlainRecord(manifest.metadata) &&
      typeof manifest.metadata.fixtureId === "string"
        ? manifest.metadata.fixtureId
        : "",
    ),
  );
  for (const binding of fixtureTruth) {
    if (!runFixtureIds.has(binding.fixtureId)) {
      throw new Error(
        `Suite index fixture truth has no bound run: ${binding.fixtureId}`,
      );
    }
  }

  const unsigned = {
    schemaVersion: 3 as const,
    suiteId: input.suiteId,
    createdAt: input.createdAt,
    runs,
    artifacts,
    fixtureTruth,
    integrity: RESEARCH_INTEGRITY_NOTICE,
  };
  const index: ResearchSuiteIndexV3 = {
    ...unsigned,
    indexSha256: sha256(canonicalJson(unsigned)),
  };
  await writeImmutableJson(
    path.join(path.resolve(suiteDirectory), SUITE_INDEX_FILE),
    index,
  );
  return index;
}

export async function validateSuiteIndex(
  suiteDirectory: string,
): Promise<{ valid: boolean; index?: ResearchSuiteIndex; errors: readonly string[] }> {
  const errors: string[] = [];
  let index: ResearchSuiteIndex;
  try {
    const indexFile = await readStableConfinedFile(
      suiteDirectory,
      SUITE_INDEX_FILE,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    index = JSON.parse(
      indexFile.content.toString("utf8"),
    ) as ResearchSuiteIndex;
  } catch (error) {
    return {
      valid: false,
      errors: [`Unable to read suite index: ${errorMessage(error)}`],
    };
  }
  try {
    validateSuiteIndexShape(index);
    const { indexSha256, ...unsigned } = index;
    if (indexSha256 !== sha256(canonicalJson(unsigned))) {
      errors.push("Suite index hash does not match its content.");
    }
  } catch (error) {
    errors.push(errorMessage(error));
  }
  if (
    index.schemaVersion === 3 &&
    Array.isArray(index.artifacts) &&
    Array.isArray(index.fixtureTruth)
  ) {
    const seen = new Set<string>();
    for (const artifact of index.artifacts) {
      if (seen.has(artifact.path)) {
        errors.push(`Suite index repeats artifact path: ${artifact.path}`);
        continue;
      }
      seen.add(artifact.path);
      try {
        assertSafeArtifactPath(
          suiteDirectory,
          artifact.path,
        );
        const integrity = await hashStableConfinedFile(
          suiteDirectory,
          artifact.path,
          { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
        );
        if (integrity.bytes !== artifact.bytes) {
          errors.push(`Suite artifact byte count changed: ${artifact.path}`);
        }
        if (integrity.sha256 !== artifact.sha256) {
          errors.push(`Suite artifact hash changed: ${artifact.path}`);
        }
      } catch (error) {
        errors.push(`${artifact.path}: ${errorMessage(error)}`);
      }
    }
    for (const binding of index.fixtureTruth) {
      const truthErrors = await validateFixtureTruthArtifact(
        suiteDirectory,
        binding,
      );
      errors.push(
        ...truthErrors.map((error) => `${binding.path}: ${error}`),
      );
    }
  }
  const expectedFiles = new Set<string>([SUITE_INDEX_FILE]);
  const boundRunFixtureIds = new Set<string>();
  if (index.schemaVersion === 3) {
    for (const artifact of index.artifacts) {
      expectedFiles.add(normalizeArtifactPath(artifact.path));
    }
  }
  for (const run of Array.isArray(index.runs) ? index.runs : []) {
    try {
      expectedFiles.add(normalizeArtifactPath(run.path));
      const manifestPath = assertSafeArtifactPath(suiteDirectory, run.path);
      const manifestFile = await readStableConfinedFile(
        suiteDirectory,
        run.path,
        { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
      );
      const manifest = JSON.parse(
        manifestFile.content.toString("utf8"),
      ) as ResearchRunManifest;
      if (
        manifest.runId !== run.runId ||
        manifest.manifestSha256 !== run.manifestSha256
      ) {
        errors.push(`Suite run binding changed: ${run.path}`);
      }
      if (
        index.schemaVersion === 3 &&
        Array.isArray(index.fixtureTruth)
      ) {
        if (
          isPlainRecord(manifest.metadata) &&
          typeof manifest.metadata.fixtureId === "string"
        ) {
          boundRunFixtureIds.add(manifest.metadata.fixtureId);
        }
        if (validateRunTruthBinding(manifest, index.fixtureTruth)) {
          errors.push(
            `Suite run truth/source binding changed: ${run.path}`,
          );
        }
      }
      const validation = await validateRunArtifacts(path.dirname(manifestPath));
      if (!validation.valid) {
        errors.push(
          `Suite run is invalid: ${run.path}: ${validation.errors.join("; ")}`,
        );
      }
      for (const artifact of Array.isArray(manifest.artifacts)
        ? manifest.artifacts
        : []) {
        expectedFiles.add(
          normalizeArtifactPath(
            path.posix.join(path.posix.dirname(run.path), artifact.path),
          ),
        );
      }
    } catch (error) {
      errors.push(`${run.path}: ${errorMessage(error)}`);
    }
  }
  if (
    index.schemaVersion === 3 &&
    Array.isArray(index.fixtureTruth)
  ) {
    for (const binding of index.fixtureTruth) {
      if (!boundRunFixtureIds.has(binding.fixtureId)) {
        errors.push(
          `Suite fixture truth has no bound run: ${binding.fixtureId}`,
        );
      }
    }
  }
  if (
    index.schemaVersion === 3 &&
    Array.isArray(index.artifacts)
  ) {
    try {
      const actualFiles = await listRunFiles(suiteDirectory);
      for (const actualFile of actualFiles) {
        if (!expectedFiles.has(actualFile)) {
          errors.push(
            `Suite directory contains an unlisted artifact: ${actualFile}`,
          );
        }
      }
      for (const expectedFile of expectedFiles) {
        if (!actualFiles.includes(expectedFile)) {
          errors.push(`Suite index references a missing artifact: ${expectedFile}`);
        }
      }
    } catch (error) {
      errors.push(`Unable to enumerate suite artifacts: ${errorMessage(error)}`);
    }
  }
  return { valid: errors.length === 0, index, errors };
}

export async function validateRunArtifacts(runDirectory: string): Promise<RunIntegrityResult> {
  const errors: string[] = [];
  let manifest: ResearchRunManifest;
  try {
    const manifestFile = await readStableConfinedFile(
      runDirectory,
      RUN_MANIFEST_FILE,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    manifest = JSON.parse(
      manifestFile.content.toString("utf8"),
    ) as ResearchRunManifest;
  } catch (error) {
    return {
      valid: false,
      errors: [`Unable to read run manifest: ${errorMessage(error)}`],
    };
  }

  try {
    validateManifestShape(manifest);
    const { manifestSha256, ...unsigned } = manifest;
    if (manifestSha256 !== sha256(canonicalJson(unsigned))) {
      errors.push("Run manifest integrity hash does not match its content.");
    }
  } catch (error) {
    errors.push(errorMessage(error));
  }

  const seen = new Set<string>();
  for (const artifact of Array.isArray(manifest.artifacts) ? manifest.artifacts : []) {
    const normalizedPath = normalizeArtifactPath(artifact.path);
    if (seen.has(normalizedPath)) {
      errors.push(`Run manifest repeats artifact path: ${artifact.path}`);
      continue;
    }
    seen.add(normalizedPath);
    if (artifact.path !== normalizedPath) {
      errors.push(`Run manifest artifact path is not canonical: ${artifact.path}`);
      continue;
    }
    try {
      assertSafeArtifactPath(runDirectory, artifact.path);
      const integrity = await hashStableConfinedFile(
        runDirectory,
        artifact.path,
        { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
      );
      if (integrity.bytes !== artifact.bytes) {
        errors.push(`Artifact byte count changed: ${artifact.path}`);
      }
      if (integrity.sha256 !== artifact.sha256) {
        errors.push(`Artifact hash changed: ${artifact.path}`);
      }
      if (artifact.path === MODEL_CALL_TRACE_FILE) {
        if (
          isPlainRecord(manifest.metadata) &&
          manifest.metadata.modelCallTraceSchemaVersion ===
            MODEL_CALL_TRACE_SCHEMA_VERSION &&
          manifest.metadata.modelCallTraceRolePlanVersion ===
            MODEL_CALL_TRACE_ROLE_PLAN_VERSION
        ) {
          errors.push(
            ...(await validateModelCallTraceArtifact(
              runDirectory,
              artifact.path,
              manifest,
            )),
          );
        } else {
          errors.push(
            "Run manifest model-call trace schema binding is unsupported.",
          );
        }
      }
    } catch (error) {
      errors.push(`${artifact.path}: ${errorMessage(error)}`);
    }
  }
  try {
    const actualFiles = await listRunFiles(runDirectory);
    const expectedFiles = new Set(
      (Array.isArray(manifest.artifacts) ? manifest.artifacts : []).map(
        (artifact) => normalizeArtifactPath(artifact.path),
      ),
    );
    for (const actualFile of actualFiles) {
      if (actualFile !== RUN_MANIFEST_FILE && !expectedFiles.has(actualFile)) {
        errors.push(`Run directory contains an unlisted artifact: ${actualFile}`);
      }
    }
  } catch (error) {
    errors.push(`Unable to enumerate run artifacts: ${errorMessage(error)}`);
  }

  return {
    valid: errors.length === 0,
    manifest,
    errors,
  };
}

function validateManifestInput(input: CreateRunManifestInput): void {
  for (const [label, value] of [
    ["runId", input.runId],
    ["suite", input.suite],
    ["mode", input.mode],
    ["harnessVersion", input.harnessVersion],
    ["promptVersion", input.promptVersion],
  ] as const) {
    if (!value.trim()) {
      throw new Error(`Run manifest ${label} must be non-empty.`);
    }
  }
  assertTimestamp(input.startedAt, "startedAt");
  assertTimestamp(input.finishedAt, "finishedAt");
  if (Date.parse(input.finishedAt) < Date.parse(input.startedAt)) {
    throw new Error("Run manifest finishedAt cannot precede startedAt.");
  }
}

function validateManifestShape(manifest: ResearchRunManifest): void {
  if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.artifacts)) {
    throw new Error("Run manifest schema is invalid.");
  }
  if (typeof manifest.manifestSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(manifest.manifestSha256)) {
    throw new Error("Run manifest integrity hash is invalid.");
  }
  validateManifestInput({
    ...manifest,
    artifactPaths: manifest.artifacts.map((artifact) => artifact.path),
  });
  if (
    !["mock", "replay", "live"].includes(manifest.execution) ||
    !["success", "partial", "degraded", "canceled", "failed"].includes(manifest.status) ||
    !Array.isArray(manifest.models) ||
    !isPlainRecord(manifest.sourceState) ||
    !isPlainRecord(manifest.limits) ||
    !isPlainRecord(manifest.metadata)
  ) {
    throw new Error("Run manifest metadata schema is invalid.");
  }
  assertIntegrityNotice(manifest.integrity);
  for (const artifact of manifest.artifacts) {
    if (
      typeof artifact.path !== "string" ||
      !Number.isSafeInteger(artifact.bytes) ||
      artifact.bytes < 0 ||
      !/^[a-f0-9]{64}$/u.test(artifact.sha256)
    ) {
      throw new Error("Run manifest contains an invalid artifact record.");
    }
  }
}

function validateSuiteIndexShape(index: ResearchSuiteIndex): void {
  if (
    ![2, 3].includes(index.schemaVersion) ||
    !index.suiteId?.trim() ||
    Number.isNaN(Date.parse(index.createdAt)) ||
    !Array.isArray(index.runs) ||
    !/^[a-f0-9]{64}$/u.test(index.indexSha256)
  ) {
    throw new Error("Suite index schema is invalid.");
  }
  assertIntegrityNotice(index.integrity);
  const paths = new Set<string>();
  const runIds = new Set<string>();
  for (const run of index.runs) {
    if (
      !run.runId?.trim() ||
      !run.path?.trim() ||
      run.path !== normalizeArtifactPath(run.path) ||
      !/^[a-f0-9]{64}$/u.test(run.manifestSha256) ||
      paths.has(run.path) ||
      runIds.has(run.runId)
    ) {
      throw new Error("Suite index contains an invalid or duplicate run binding.");
    }
    paths.add(run.path);
    runIds.add(run.runId);
  }
  if (index.schemaVersion === 3) {
    if (!Array.isArray(index.artifacts) || !Array.isArray(index.fixtureTruth)) {
      throw new Error("Suite index v3 artifact bindings are missing.");
    }
    const artifactPaths = new Set<string>();
    for (const artifact of index.artifacts) {
      validateArtifactRecord(artifact, "Suite index");
      if (
        artifact.path !== normalizeArtifactPath(artifact.path) ||
        artifactPaths.has(artifact.path)
      ) {
        throw new Error(
          "Suite index v3 contains an invalid or duplicate artifact path.",
        );
      }
      artifactPaths.add(artifact.path);
    }
    for (const required of REQUIRED_SUITE_ARTIFACTS) {
      if (!artifactPaths.has(required)) {
        throw new Error(
          `Suite index v3 is missing required artifact: ${required}`,
        );
      }
    }
    const fixtureIds = new Set<string>();
    const truthPaths = new Set<string>();
    for (const binding of index.fixtureTruth) {
      const artifact = index.artifacts.find(
        (candidate) => candidate.path === binding.path,
      );
      const structuralFields = [
        binding.projectRoot,
        binding.projectDigestSha256,
        binding.evaluatorDigestSha256,
        binding.layoutBindingSha256,
      ];
      const structuralFieldCount = structuralFields.filter(
        (value) => value !== undefined,
      ).length;
      if (
        !binding.fixtureId?.trim() ||
        !binding.pairId?.trim() ||
        !["vulnerable", "clean"].includes(binding.variant) ||
        binding.path !== normalizeArtifactPath(binding.path) ||
        !artifact ||
        binding.artifactSha256 !== artifact.sha256 ||
        !/^[a-f0-9]{64}$/u.test(binding.fixtureDigestSha256) ||
        fixtureIds.has(binding.fixtureId) ||
        truthPaths.has(binding.path)
      ) {
        throw new Error(
          "Suite index v3 contains an invalid or duplicate fixture truth binding.",
        );
      }
      if (
        structuralFieldCount !== 0 &&
        (structuralFieldCount !== structuralFields.length ||
          binding.projectRoot !== "project" ||
          !isSha256(binding.projectDigestSha256) ||
          !isSha256(binding.evaluatorDigestSha256) ||
          !isSha256(binding.layoutBindingSha256))
      ) {
        throw new Error(
          "Suite index v3 contains an incomplete structural fixture truth binding.",
        );
      }
      fixtureIds.add(binding.fixtureId);
      truthPaths.add(binding.path);
    }
    if (index.fixtureTruth.length === 0) {
      throw new Error(
        "Suite index v3 requires at least one fixture truth binding.",
      );
    }
    for (const artifact of index.artifacts) {
      if (
        artifact.path.startsWith("truth/") &&
        !truthPaths.has(artifact.path)
      ) {
        throw new Error(
          "Suite index v3 contains an unbound fixture truth artifact.",
        );
      }
    }
  }
}

function validateArtifactRecord(
  artifact: RunArtifactRecord,
  label: string,
): void {
  if (
    typeof artifact.path !== "string" ||
    !artifact.path.trim() ||
    !Number.isSafeInteger(artifact.bytes) ||
    artifact.bytes < 0 ||
    !/^[a-f0-9]{64}$/u.test(artifact.sha256)
  ) {
    throw new Error(`${label} contains an invalid artifact record.`);
  }
}

async function validateFixtureTruthArtifact(
  suiteDirectory: string,
  binding: ResearchSuiteTruthBinding,
): Promise<string[]> {
  const errors: string[] = [];
  let parsed: unknown;
  try {
    assertSafeArtifactPath(
      suiteDirectory,
      binding.path,
    );
    const truthFile = await readStableConfinedFile(
      suiteDirectory,
      binding.path,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    parsed = JSON.parse(
      truthFile.content.toString("utf8"),
    ) as unknown;
  } catch (error) {
    return [`Unable to read fixture truth artifact: ${errorMessage(error)}`];
  }
  if (!isPlainRecord(parsed) || parsed.schemaVersion !== "1.0") {
    return ["Fixture truth artifact schema is invalid."];
  }
  if (
    !Array.isArray(parsed.redactionMarkers) ||
    parsed.redactionMarkers.some(
      (marker) => typeof marker !== "string",
    ) ||
    !isPlainRecord(parsed.data)
  ) {
    return ["Fixture truth artifact redaction envelope is invalid."];
  }
  const data = parsed.data;
  const manifest = isPlainRecord(data.manifest)
    ? data.manifest
    : undefined;
  const truth = isPlainRecord(data.truth) ? data.truth : undefined;
  const sourceState = isPlainRecord(data.sourceState)
    ? data.sourceState
    : undefined;
  const internalBinding = isPlainRecord(data.binding)
    ? data.binding
    : undefined;
  if (
    data.fixtureId !== binding.fixtureId ||
    data.pairId !== binding.pairId ||
    data.variant !== binding.variant ||
    manifest?.id !== binding.fixtureId ||
    truth?.fixtureId !== binding.fixtureId ||
    sourceState?.fixtureId !== binding.fixtureId
  ) {
    errors.push("Fixture truth identity binding is invalid.");
  }
  if (
    !manifest ||
    !truth ||
    !sourceState ||
    !internalBinding ||
    sourceState.fixtureDigestSha256 !== binding.fixtureDigestSha256 ||
    internalBinding.fixtureDigestSha256 !==
      binding.fixtureDigestSha256
  ) {
    errors.push("Fixture truth source binding is invalid.");
    return errors;
  }
  if (
    internalBinding.manifestSha256 !==
      sha256(canonicalJson(manifest)) ||
    internalBinding.truthSha256 !== sha256(canonicalJson(truth)) ||
    internalBinding.sourceStateSha256 !==
      sha256(canonicalJson(sourceState))
  ) {
    errors.push("Fixture truth internal content binding is invalid.");
  }
  if (isPlainRecord(sourceState.project)) {
    const projectError = validateStructuralProjectSourceState(
      sourceState,
      internalBinding,
      manifest,
    );
    if (projectError) {
      errors.push(projectError);
    }
    const project = sourceState.project;
    const evaluator = isPlainRecord(sourceState.evaluator)
      ? sourceState.evaluator
      : undefined;
    if (
      binding.projectRoot !== project.root ||
      binding.projectDigestSha256 !==
        project.projectDigestSha256 ||
      binding.evaluatorDigestSha256 !==
        evaluator?.evaluatorDigestSha256 ||
      binding.layoutBindingSha256 !==
        sourceState.layoutBindingSha256
    ) {
      errors.push(
        "Fixture truth structural suite binding is invalid.",
      );
    }
  } else if (isPlainRecord(sourceState.subject)) {
    const subjectError = validateSubjectSourceState(
      sourceState,
      internalBinding,
    );
    if (subjectError) {
      errors.push(subjectError);
    }
  }
  if (
    typeof manifest.expectedFindingCount !== "number" ||
    !Array.isArray(truth.findings) ||
    manifest.expectedFindingCount !== truth.findings.length
  ) {
    errors.push("Fixture truth finding-count binding is invalid.");
  }
  return errors;
}

function validateRunTruthBinding(
  manifest: ResearchRunManifest,
  fixtureTruth: readonly ResearchSuiteTruthBinding[],
): string | undefined {
  const fixtureId =
    isPlainRecord(manifest.metadata) &&
    typeof manifest.metadata.fixtureId === "string"
      ? manifest.metadata.fixtureId
      : "";
  const truthBinding = fixtureTruth.find(
    (candidate) => candidate.fixtureId === fixtureId,
  );
  const metadataTruth = isPlainRecord(manifest.metadata.truthArtifact)
    ? manifest.metadata.truthArtifact
    : undefined;
  const sourceDigest =
    isPlainRecord(manifest.sourceState) &&
    typeof manifest.sourceState.fixtureDigestSha256 === "string"
      ? manifest.sourceState.fixtureDigestSha256
      : "";
  const requiresProjectSnapshot =
    isPlainRecord(manifest.metadata) &&
    manifest.metadata.projectSnapshotSchemaVersion === "1.0";
  const projectMetadata =
    isPlainRecord(manifest.metadata) &&
    isPlainRecord(manifest.metadata.projectSnapshot)
      ? manifest.metadata.projectSnapshot
      : undefined;
  const projectBindingError = requiresProjectSnapshot
    ? validateStructuralProjectSourceState(manifest.sourceState)
    : undefined;
  const sourceProject = isPlainRecord(manifest.sourceState.project)
    ? manifest.sourceState.project
    : undefined;
  const sourceEvaluator = isPlainRecord(manifest.sourceState.evaluator)
    ? manifest.sourceState.evaluator
    : undefined;
  const requiresSubjectSnapshot =
    isPlainRecord(manifest.metadata) &&
    manifest.metadata.subjectSnapshotSchemaVersion === "1.0";
  const subjectMetadata =
    isPlainRecord(manifest.metadata) &&
    isPlainRecord(manifest.metadata.subjectSnapshot)
      ? manifest.metadata.subjectSnapshot
      : undefined;
  const subjectBindingError = requiresSubjectSnapshot
    ? validateSubjectSourceState(manifest.sourceState)
    : undefined;
  const sourceSubject = isPlainRecord(manifest.sourceState.subject)
    ? manifest.sourceState.subject
    : undefined;
  if (
    !truthBinding ||
    metadataTruth?.fixtureId !== fixtureId ||
    metadataTruth.path !== truthBinding.path ||
    metadataTruth.fixtureDigestSha256 !==
      truthBinding.fixtureDigestSha256 ||
    sourceDigest !== truthBinding.fixtureDigestSha256
  ) {
    return "run metadata/source state does not match canonical fixture truth";
  }
  if (
    requiresProjectSnapshot &&
    (projectBindingError ||
      !sourceProject ||
      !sourceEvaluator ||
      !projectMetadata ||
      truthBinding.projectRoot !== sourceProject.root ||
      truthBinding.projectDigestSha256 !==
        sourceProject.projectDigestSha256 ||
      truthBinding.evaluatorDigestSha256 !==
        sourceEvaluator.evaluatorDigestSha256 ||
      truthBinding.layoutBindingSha256 !==
        manifest.sourceState.layoutBindingSha256 ||
      metadataTruth.projectRoot !== truthBinding.projectRoot ||
      metadataTruth.projectDigestSha256 !==
        truthBinding.projectDigestSha256 ||
      metadataTruth.evaluatorDigestSha256 !==
        truthBinding.evaluatorDigestSha256 ||
      metadataTruth.layoutBindingSha256 !==
        truthBinding.layoutBindingSha256 ||
      projectMetadata.root !== sourceProject.root ||
      projectMetadata.projectDigestSha256 !==
        sourceProject.projectDigestSha256 ||
      projectMetadata.evaluatorDigestSha256 !==
        sourceEvaluator.evaluatorDigestSha256 ||
      projectMetadata.layoutBindingSha256 !==
        manifest.sourceState.layoutBindingSha256)
  ) {
    return (
      projectBindingError ??
      "run metadata/source state does not match the structural project snapshot"
    );
  }
  if (
    requiresSubjectSnapshot &&
    (subjectBindingError ||
      !sourceSubject ||
      !subjectMetadata ||
      subjectMetadata.subjectDigestSha256 !==
        sourceSubject.subjectDigestSha256 ||
      subjectMetadata.fixtureBindingSha256 !==
        sourceSubject.fixtureBindingSha256)
  ) {
    return (
      subjectBindingError ??
      "run metadata/source state does not match the project-only subject snapshot"
    );
  }
  return undefined;
}

function validateSubjectSourceState(
  sourceState: Readonly<Record<string, unknown>>,
  internalBinding?: Readonly<Record<string, unknown>>,
): string | undefined {
  const subject = isPlainRecord(sourceState.subject)
    ? sourceState.subject
    : undefined;
  const fullFiles = provenanceFiles(sourceState.files);
  const subjectFiles = provenanceFiles(subject?.files);
  const excludedControlFiles = Array.isArray(
    subject?.excludedControlFiles,
  )
    ? subject.excludedControlFiles
    : undefined;
  if (
    !subject ||
    !fullFiles ||
    !subjectFiles ||
    !excludedControlFiles ||
    excludedControlFiles.some(
      (entry) => typeof entry !== "string",
    ) ||
    !isCanonicalUniqueOrder(
      excludedControlFiles as readonly string[],
    )
  ) {
    return "Project-only subject provenance schema is invalid.";
  }
  const expectedSubjectFiles = fullFiles.filter(
    (file) => !isEvaluationControlPath(file.path),
  );
  const expectedExcluded = fullFiles
    .filter((file) => isEvaluationControlPath(file.path))
    .map((file) => file.path);
  if (
    expectedExcluded.length === 0 ||
    !expectedExcluded.includes("fixture.json") ||
    !expectedExcluded.includes("truth.json") ||
    canonicalJson(subjectFiles) !== canonicalJson(expectedSubjectFiles) ||
    canonicalJson(excludedControlFiles) !==
      canonicalJson(expectedExcluded) ||
    subjectFiles.some((file) =>
      isEvaluationControlPath(file.path),
    )
  ) {
    return "Project-only subject provenance leaks or omits evaluator-controlled files.";
  }
  const fixtureDigestSha256 = sha256(
    prettyCanonicalJson(fullFiles),
  );
  const subjectDigestSha256 = sha256(
    prettyCanonicalJson(subjectFiles),
  );
  const fixtureBindingSha256 = sha256(
    canonicalJson({
      fixtureDigestSha256,
      subjectDigestSha256,
      excludedControlFiles: expectedExcluded,
    }),
  );
  if (
    sourceState.fixtureDigestSha256 !== fixtureDigestSha256 ||
    subject.subjectDigestSha256 !== subjectDigestSha256 ||
    subject.fixtureBindingSha256 !== fixtureBindingSha256 ||
    (internalBinding !== undefined &&
      (internalBinding.subjectDigestSha256 !==
        subjectDigestSha256 ||
        internalBinding.subjectFixtureBindingSha256 !==
          fixtureBindingSha256))
  ) {
    return "Project-only subject provenance digest binding is invalid.";
  }
  return undefined;
}

function validateStructuralProjectSourceState(
  sourceState: Readonly<Record<string, unknown>>,
  internalBinding?: Readonly<Record<string, unknown>>,
  manifest?: Readonly<Record<string, unknown>>,
): string | undefined {
  const project = isPlainRecord(sourceState.project)
    ? sourceState.project
    : undefined;
  const evaluator = isPlainRecord(sourceState.evaluator)
    ? sourceState.evaluator
    : undefined;
  const fullFiles = provenanceFiles(sourceState.files);
  const projectFiles = provenanceFiles(project?.files);
  const evaluatorFiles = provenanceFiles(evaluator?.files);
  if (sourceState.schemaVersion !== "2.0") {
    return "Structural project provenance schemaVersion is invalid.";
  }
  if (!project || !evaluator || project.root !== "project") {
    return "Structural project provenance boundary objects are invalid.";
  }
  if (!fullFiles || !projectFiles || !evaluatorFiles) {
    return `Structural project provenance file records are invalid (${[
      !fullFiles ? "fixture" : "",
      !projectFiles ? "project" : "",
      !evaluatorFiles ? "evaluator" : "",
    ]
      .filter(Boolean)
      .join(", ")}).`;
  }

  const prefix = "project/";
  const expectedProjectFiles = fullFiles
    .filter((file) => file.path.startsWith(prefix))
    .map((file) => ({
      ...file,
      path: file.path.slice(prefix.length),
    }));
  const expectedEvaluatorFiles = fullFiles.filter(
    (file) => !file.path.startsWith(prefix),
  );
  if (
    expectedProjectFiles.length === 0 ||
    !expectedEvaluatorFiles.some(
      (file) => file.path === "fixture.json",
    ) ||
    !expectedEvaluatorFiles.some(
      (file) => file.path === "truth.json",
    ) ||
    canonicalJson(projectFiles) !==
      canonicalJson(expectedProjectFiles) ||
    canonicalJson(evaluatorFiles) !==
      canonicalJson(expectedEvaluatorFiles)
  ) {
    return "Structural project provenance leaks, aliases, or omits fixture files.";
  }

  if (manifest) {
    const declaredEvaluatorFiles = Array.isArray(
      manifest.evaluatorFiles,
    )
      ? manifest.evaluatorFiles
      : undefined;
    if (
      manifest.projectRoot !== "project" ||
      !declaredEvaluatorFiles ||
      declaredEvaluatorFiles.some(
        (entry) => typeof entry !== "string",
      ) ||
      canonicalJson(
        expectedEvaluatorFiles.map((file) => file.path),
      ) !==
        canonicalJson(
          ["fixture.json", ...declaredEvaluatorFiles].sort(),
        )
    ) {
      return "Structural evaluator provenance does not match the fixture manifest.";
    }
  }

  const fixtureDigestSha256 = sha256(
    prettyCanonicalJson(fullFiles),
  );
  const projectDigestSha256 = sha256(
    prettyCanonicalJson(projectFiles),
  );
  const evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(evaluatorFiles),
  );
  const layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: "project",
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  if (
    sourceState.fixtureDigestSha256 !== fixtureDigestSha256 ||
    project.projectDigestSha256 !== projectDigestSha256 ||
    evaluator.evaluatorDigestSha256 !== evaluatorDigestSha256 ||
    sourceState.layoutBindingSha256 !== layoutBindingSha256 ||
    (internalBinding !== undefined &&
      (internalBinding.projectRoot !== "project" ||
        internalBinding.projectDigestSha256 !==
          projectDigestSha256 ||
        internalBinding.evaluatorDigestSha256 !==
          evaluatorDigestSha256 ||
        internalBinding.layoutBindingSha256 !==
          layoutBindingSha256))
  ) {
    return "Structural project/evaluator provenance digest binding is invalid.";
  }

  const subject = isPlainRecord(sourceState.subject)
    ? sourceState.subject
    : undefined;
  if (
    subject &&
    (canonicalJson(provenanceFiles(subject.files)) !==
      canonicalJson(projectFiles) ||
      subject.subjectDigestSha256 !== projectDigestSha256 ||
      subject.fixtureBindingSha256 !== layoutBindingSha256 ||
      canonicalJson(subject.excludedControlFiles) !==
        canonicalJson(
          evaluatorFiles.map((file) => file.path),
        ))
  ) {
    return "Structural project compatibility alias is inconsistent.";
  }
  return undefined;
}

function provenanceFiles(
  value: unknown,
): RunArtifactRecord[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const records: RunArtifactRecord[] = [];
  for (const candidate of value) {
    if (!isPlainRecord(candidate)) {
      return undefined;
    }
    const record = {
      path: candidate.path,
      bytes: candidate.bytes,
      sha256: candidate.sha256,
    };
    if (
      typeof record.path !== "string" ||
      record.path !== normalizeArtifactPath(record.path) ||
      path.posix.isAbsolute(record.path) ||
      record.path === ".." ||
      record.path.startsWith("../") ||
      !Number.isSafeInteger(record.bytes) ||
      (record.bytes as number) < 0 ||
      typeof record.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(record.sha256)
    ) {
      return undefined;
    }
    records.push(record as RunArtifactRecord);
  }
  if (
    records.length === 0 ||
    !isCanonicalUniqueOrder(records.map((record) => record.path)) ||
    new Set(records.map((record) => record.path.toLowerCase())).size !==
      records.length
  ) {
    return undefined;
  }
  return records;
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function isEvaluationControlPath(relativePath: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const basename = normalized.split("/").at(-1) ?? "";
  return (
    [
      "fixture.json",
      "truth.json",
      "groundtruth.json",
      "groundtruth.yml",
      "groundtruth.yaml",
      "hermsec-fixture.json",
      "answer-key.json",
      "expected-findings.json",
    ].includes(basename) ||
    /^(?:ground[-_.]?truth|answer[-_.]?key|expected[-_.]?findings?|evaluation[-_.]?labels?)\.(?:json|ya?ml|toml)$/u.test(
      basename,
    )
  );
}

function isCanonicalUniqueOrder(values: readonly string[]): boolean {
  return (
    new Set(values).size === values.length &&
    canonicalJson(values) ===
      canonicalJson([...values].sort((left, right) =>
        left.localeCompare(right),
      ))
  );
}

async function validateModelCallTraceArtifact(
  runDirectory: string,
  relativePath: string,
  manifest: ResearchRunManifest,
): Promise<string[]> {
  let document: unknown;
  try {
    const traceFile = await readStableConfinedFile(
      runDirectory,
      relativePath,
      { maxBytes: MAX_RESEARCH_ARTIFACT_BYTES },
    );
    document = JSON.parse(
      traceFile.content.toString("utf8"),
    ) as unknown;
  } catch (error) {
    return [
      `Unable to read model-call trace: ${errorMessage(error)}`,
    ];
  }
  if (
    !isPlainRecord(document) ||
    document.schemaVersion !== "1.0" ||
    !isPlainRecord(document.data)
  ) {
    return ["Model-call trace envelope is invalid."];
  }
  const trace = document.data as unknown as ResearchModelCallTrace;
  if (
    !isPlainRecord(trace) ||
    !isPlainRecord(trace.producerValidation) ||
    !Array.isArray(trace.calls) ||
    !Array.isArray(trace.derivedFrom) ||
    typeof trace.producerValidation.valid !== "boolean" ||
    !Array.isArray(trace.producerValidation.errors) ||
    trace.producerValidation.errors.some(
      (error) => typeof error !== "string",
    ) ||
    canonicalJson(
      Object.keys(trace.producerValidation).sort(),
    ) !== canonicalJson(["errors", "valid"])
  ) {
    return ["Model-call trace schema is invalid."];
  }
  if (
    !isPlainRecord(manifest.metadata) ||
    trace.schemaVersion !==
      manifest.metadata.modelCallTraceSchemaVersion
  ) {
    return [
      "Model-call trace schema does not match its manifest binding.",
    ];
  }
  const { producerValidation, ...draft } = trace;
  let recomputed: string[];
  try {
    recomputed = validateModelCallTrace(draft);
  } catch {
    return ["Model-call trace schema is invalid."];
  }
  const recordedErrors =
    producerValidation.errors as readonly string[];
  const errors: string[] = [];
  if (
    producerValidation.valid !== (recomputed.length === 0) ||
    canonicalJson(recordedErrors) !== canonicalJson(recomputed)
  ) {
    errors.push("Model-call trace producer validation changed.");
  }
  const metadataPhysical =
    isPlainRecord(manifest.metadata) &&
    typeof manifest.metadata.physical === "boolean"
      ? manifest.metadata.physical
      : undefined;
  const metadataDerived =
    isPlainRecord(manifest.metadata) &&
    Array.isArray(manifest.metadata.derivedFrom)
      ? manifest.metadata.derivedFrom
      : undefined;
  if (
    trace.runId !== manifest.runId ||
    trace.mode !== manifest.mode ||
    trace.execution !== manifest.execution ||
    trace.cassettePolicy !==
      (isPlainRecord(manifest.metadata)
        ? manifest.metadata.modelCallTraceCassettePolicy
        : undefined) ||
    trace.physical !== metadataPhysical ||
    canonicalJson(trace.derivedFrom) !==
      canonicalJson(metadataDerived ?? [])
  ) {
    errors.push("Model-call trace run binding changed.");
  }
  if (manifest.status === "success" && recomputed.length > 0) {
    errors.push(
      "Successful run contains an invalid model-call trace.",
    );
  }
  return errors;
}

function assertIntegrityNotice(notice: ResearchIntegrityNotice): void {
  if (
    notice?.kind !== RESEARCH_INTEGRITY_NOTICE.kind ||
    notice.authenticated !== false ||
    notice.notice !== RESEARCH_INTEGRITY_NOTICE.notice
  ) {
    throw new Error("Research artifact integrity semantics are missing or misleading.");
  }
}

async function listRunFiles(runDirectory: string): Promise<string[]> {
  return listStableTreeFiles(
    runDirectory,
    RESEARCH_ARTIFACT_TREE_LIMITS,
  );
}

function normalizeArtifactPath(relativePath: string): string {
  const slashPath = relativePath.replaceAll("\\", "/");
  return path.posix.normalize(slashPath);
}

function assertTimestamp(value: string, label: string): void {
  if (!value || Number.isNaN(Date.parse(value))) {
    throw new Error(`Run manifest ${label} must be a valid timestamp.`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
