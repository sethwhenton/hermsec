import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { redactForLog } from "../agent/redaction.js";
import type { ModelRequest, ModelResponse } from "../model/provider.js";
import {
  canonicalJson,
  prettyCanonicalJson,
  recoverImmutableJsonTemps,
  sha256,
  writeImmutableJson,
} from "./integrity.js";

export type ReplayRequest = {
  provider: string;
  model: string;
  request: ModelRequest;
};

export type ReplayCassette = {
  schemaVersion: 2;
  requestFingerprint: string;
  occurrence: number;
  scopeIdSha256?: string;
  provider: string;
  model: string;
  createdAt: string;
  request: unknown;
  response: ModelResponse;
  redactionMarkers: readonly string[];
  integritySha256: string;
};

export type ReplayReference = {
  requestFingerprint: string;
  occurrence: number;
  relativePath: string;
  integritySha256: string;
  scopeIdSha256?: string;
};

export type ReplayCassetteStoreOptions = {
  cursorId?: string;
  scopeId?: string;
  lockTimeoutMs?: number;
  staleLockMs?: number;
  retryDelayMs?: number;
};

const REPLAY_REFERENCE_SYMBOL: unique symbol = Symbol(
  "hermsec.replay-reference",
);

type ReplayCursorSnapshot = {
  schemaVersion: 2;
  cursorIdSha256: string;
  sequence: number;
  previousDigestSha256: string | null;
  occurrences: Readonly<Record<string, number>>;
  digestSha256: string;
};

export class ReplayInputRejectedError extends Error {
  readonly markers: readonly string[];

  constructor(markers: readonly string[]) {
    super(
      "Replay request contains secret-bearing or redactable material and was rejected before fingerprinting.",
    );
    this.name = "ReplayInputRejectedError";
    this.markers = [...markers];
  }
}

export class ReplayCassetteStore {
  readonly directory: string;
  readonly lockPath: string;
  private readonly cursorIdSha256: string | undefined;
  private readonly scopeIdSha256: string | undefined;
  private readonly lockTimeoutMs: number;
  private readonly staleLockMs: number;
  private readonly retryDelayMs: number;
  private canonicalRoot?: string;

  constructor(directory: string, options: ReplayCassetteStoreOptions = {}) {
    this.directory = path.resolve(directory);
    this.lockPath = path.join(this.directory, ".replay.lock");
    this.cursorIdSha256 = options.cursorId
      ? sha256(`hermsec-replay-cursor\u0000${options.cursorId}`)
      : undefined;
    this.scopeIdSha256 = options.scopeId
      ? sha256(`hermsec-replay-scope\u0000${options.scopeId}`)
      : undefined;
    this.lockTimeoutMs = options.lockTimeoutMs ?? 10_000;
    this.staleLockMs = options.staleLockMs ?? 120_000;
    this.retryDelayMs = options.retryDelayMs ?? 15;
  }

  async record(
    input: ReplayRequest & { response: ModelResponse },
  ): Promise<ReplayReference> {
    const prepared = prepareRequest(input, this.scopeIdSha256);
    return this.withLock(async (root) => {
      await this.recoverUnlocked(root);
      const occurrence =
        (await highestRecordedOccurrence(root, prepared.requestFingerprint)) + 1;
      const relativePath = cassetteFileName(
        prepared.requestFingerprint,
        occurrence,
      );
      const filePath = confinedPath(root, relativePath);
      const sanitizedResponse = sanitizeReplayValue(input.response);
      const unsigned = {
        schemaVersion: 2 as const,
        requestFingerprint: prepared.requestFingerprint,
        ...(prepared.scopeIdSha256
          ? { scopeIdSha256: prepared.scopeIdSha256 }
          : {}),
        occurrence,
        provider: input.provider,
        model: input.model,
        createdAt: new Date().toISOString(),
        request: prepared.request,
        response: cloneJson(sanitizedResponse.value) as ModelResponse,
        redactionMarkers: [...new Set(sanitizedResponse.markers)].sort(),
      };
      const cassette: ReplayCassette = {
        ...unsigned,
        integritySha256: sha256(canonicalJson(unsigned)),
      };
      await writeImmutableJson(filePath, cassette);
      return replayReference(cassette, relativePath);
    });
  }

  async replay(input: ReplayRequest): Promise<ModelResponse> {
    return (await this.replayWithReference(input)).response;
  }

  async replayWithReference(
    input: ReplayRequest,
  ): Promise<{ response: ModelResponse; reference: ReplayReference }> {
    const prepared = prepareRequest(input, this.scopeIdSha256);
    if (!this.cursorIdSha256) {
      throw new Error(
        "Replay execution requires a stable cursorId so occurrences survive restarts.",
      );
    }
    return this.withLock(async (root) => {
      await this.recoverUnlocked(root);
      const cursor = await readCursorChain(root, this.cursorIdSha256 as string);
      const occurrence =
        (cursor?.occurrences[prepared.requestFingerprint] ?? 0) + 1;
      const filePath = confinedPath(
        root,
        cassetteFileName(prepared.requestFingerprint, occurrence),
      );
      const cassette = await readCassette(filePath, root);
      if (
        cassette.requestFingerprint !== prepared.requestFingerprint ||
        cassette.occurrence !== occurrence ||
        cassette.scopeIdSha256 !== prepared.scopeIdSha256 ||
        cassette.provider !== input.provider ||
        cassette.model !== input.model
      ) {
        throw new Error(
          "Replay cassette does not match the requested provider, model, or call.",
        );
      }

      const nextOccurrences = {
        ...(cursor?.occurrences ?? {}),
        [prepared.requestFingerprint]: occurrence,
      };
      await writeCursorSnapshot(root, this.cursorIdSha256 as string, {
        sequence: (cursor?.sequence ?? 0) + 1,
        previousDigestSha256: cursor?.digestSha256 ?? null,
        occurrences: nextOccurrences,
      });
      return {
        response: cloneJson(cassette.response) as ModelResponse,
        reference: replayReference(
          cassette,
          cassetteFileName(prepared.requestFingerprint, occurrence),
        ),
      };
    });
  }

  fingerprint(input: ReplayRequest): string {
    return prepareRequest(input, this.scopeIdSha256).requestFingerprint;
  }

  async validateReference(reference: ReplayReference): Promise<void> {
    await this.withLock(async (root) => {
      const filePath = confinedPath(root, reference.relativePath);
      const cassette = await readCassette(filePath, root);
      const expected = replayReference(cassette, reference.relativePath);
      if (canonicalJson(expected) !== canonicalJson(reference)) {
        throw new Error("Replay reference does not match its cassette.");
      }
      if (reference.scopeIdSha256 !== this.scopeIdSha256) {
        throw new Error("Replay reference does not match the configured cassette scope.");
      }
    });
  }

  async recover(): Promise<number> {
    return this.withLock((root) => this.recoverUnlocked(root));
  }

  private async recoverUnlocked(root: string): Promise<number> {
    let recovered = await recoverImmutableJsonTemps(root);
    const cursorDirectory = path.join(root, ".replay-cursors");
    await assertOptionalDirectoryNotSymlink(cursorDirectory);
    recovered += await recoverImmutableJsonTemps(cursorDirectory);
    return recovered;
  }

  private async withLock<T>(
    operation: (canonicalRoot: string) => Promise<T>,
  ): Promise<T> {
    const root = await this.ensureRoot();
    const token = randomUUID();
    const startedAt = Date.now();
    while (true) {
      try {
        await fs.mkdir(this.lockPath);
      } catch (error) {
        if (!isRetryableLockContentionError(error)) {
          throw error;
        }
        if (isFileExistsError(error)) {
          await this.reclaimStaleLock();
        }
        if (Date.now() - startedAt >= this.lockTimeoutMs) {
          throw new Error(`Timed out waiting for replay lock: ${this.lockPath}`);
        }
        await delay(this.retryDelayMs + Math.floor(Math.random() * this.retryDelayMs));
        continue;
      }

      try {
        await fs.writeFile(
          path.join(this.lockPath, "owner.json"),
          JSON.stringify({
            token,
            pid: process.pid,
            createdAt: new Date().toISOString(),
          }),
          { encoding: "utf8", flag: "wx" },
        );
        break;
      } catch (error) {
        await this.cleanupFailedLockInitialization(token);
        if (!isRetryableWindowsLockError(error)) {
          throw error;
        }
        if (Date.now() - startedAt >= this.lockTimeoutMs) {
          throw new Error(
            `Timed out initializing replay lock ownership: ${this.lockPath}`,
          );
        }
        await delay(this.retryDelayMs + Math.floor(Math.random() * this.retryDelayMs));
      }
    }
    try {
      return await operation(root);
    } finally {
      await this.releaseLock(token);
    }
  }

  private async ensureRoot(): Promise<string> {
    await fs.mkdir(this.directory, { recursive: true });
    const stat = await fs.lstat(this.directory);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error("Replay cassette root must be a real directory, not a link.");
    }
    const real = await fs.realpath(this.directory);
    if (this.canonicalRoot && !samePath(this.canonicalRoot, real)) {
      throw new Error("Replay cassette root changed its canonical destination.");
    }
    this.canonicalRoot = real;
    return real;
  }

  private async reclaimStaleLock(): Promise<void> {
    let stat;
    try {
      stat = await fs.stat(this.lockPath);
    } catch (error) {
      if (isMissingFileError(error)) {
        return;
      }
      throw error;
    }
    if (Date.now() - stat.mtimeMs < this.staleLockMs) {
      return;
    }
    const owner = await readLockOwner(this.lockPath);
    if (owner && isProcessAlive(owner.pid)) {
      return;
    }
    const quarantine = `${this.lockPath}.stale-${randomUUID()}`;
    try {
      await fs.rename(this.lockPath, quarantine);
      await fs.rm(quarantine, { recursive: true, force: true });
    } catch (error) {
      if (!isMissingFileError(error)) {
        throw error;
      }
    }
  }

  private async releaseLock(token: string): Promise<void> {
    const owner = await readLockOwner(this.lockPath);
    if (!owner || owner.token !== token) {
      throw new Error("Replay lock ownership changed before release.");
    }
    await fs.rm(this.lockPath, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: this.retryDelayMs,
    });
  }

  private async cleanupFailedLockInitialization(token: string): Promise<void> {
    const owner = await readLockOwner(this.lockPath);
    if (owner && owner.token !== token) {
      throw new Error(
        "Replay lock ownership changed during failed initialization.",
      );
    }
    await fs.rm(this.lockPath, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: this.retryDelayMs,
    });
  }
}

export function fingerprintReplayRequest(input: ReplayRequest): string {
  return prepareRequest(input).requestFingerprint;
}

export function attachReplayReference(
  response: ModelResponse,
  reference: ReplayReference,
): ModelResponse {
  const attached = { ...response };
  Object.defineProperty(attached, REPLAY_REFERENCE_SYMBOL, {
    value: Object.freeze({ ...reference }),
    configurable: false,
    enumerable: false,
    writable: false,
  });
  return attached;
}

export function replayReferenceFromResponse(
  response: ModelResponse,
): ReplayReference | undefined {
  const value = (response as ModelResponse & {
    [REPLAY_REFERENCE_SYMBOL]?: ReplayReference;
  })[REPLAY_REFERENCE_SYMBOL];
  return value ? { ...value } : undefined;
}

export async function validateReplayCassette(
  filePath: string,
): Promise<ReplayCassette> {
  const stat = await fs.lstat(filePath);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error("Replay cassette must be a regular file, not a link.");
  }
  return readCassette(filePath);
}

async function readCassette(
  filePath: string,
  root?: string,
): Promise<ReplayCassette> {
  if (root) {
    await assertConfinedRegularFile(root, filePath);
  }
  const parsed = JSON.parse(await fs.readFile(filePath, "utf8")) as ReplayCassette;
  if (
    parsed.schemaVersion !== 2 ||
    typeof parsed.requestFingerprint !== "string" ||
    !/^[a-f0-9]{64}$/u.test(parsed.requestFingerprint) ||
    (parsed.scopeIdSha256 !== undefined &&
      (typeof parsed.scopeIdSha256 !== "string" ||
        !/^[a-f0-9]{64}$/u.test(parsed.scopeIdSha256))) ||
    !Number.isSafeInteger(parsed.occurrence) ||
    parsed.occurrence < 1 ||
    typeof parsed.provider !== "string" ||
    typeof parsed.model !== "string" ||
    typeof parsed.integritySha256 !== "string"
  ) {
    throw new Error(`Replay cassette has an invalid schema: ${filePath}`);
  }
  const { integritySha256, ...unsigned } = parsed;
  const expected = sha256(canonicalJson(unsigned));
  if (integritySha256 !== expected) {
    throw new Error(`Replay cassette integrity validation failed: ${filePath}`);
  }
  const requestFingerprint = prepareRequest(
    {
      provider: parsed.provider,
      model: parsed.model,
      request: parsed.request as ModelRequest,
    },
    parsed.scopeIdSha256,
  ).requestFingerprint;
  if (requestFingerprint !== parsed.requestFingerprint) {
    throw new Error(`Replay cassette request fingerprint is invalid: ${filePath}`);
  }
  const sanitizedResponse = sanitizeReplayValue(parsed.response);
  if (
    canonicalJson(sanitizedResponse.value) !== canonicalJson(parsed.response)
  ) {
    throw new Error(
      `Replay cassette contains unsanitized sensitive material: ${filePath}`,
    );
  }
  return parsed;
}

function prepareRequest(
  input: ReplayRequest,
  scopeIdSha256?: string,
): {
  requestFingerprint: string;
  request: unknown;
  scopeIdSha256?: string;
} {
  const raw = {
    provider: input.provider,
    model: input.model,
    ...(scopeIdSha256 ? { scopeIdSha256 } : {}),
    request: input.request,
  };
  const sanitized = sanitizeReplayValue(raw);
  if (sanitized.redacted || sanitized.markers.length > 0) {
    throw new ReplayInputRejectedError(sanitized.markers);
  }
  const cloned = cloneJson(raw) as {
    provider: string;
    model: string;
    request: unknown;
    scopeIdSha256?: string;
  };
  return {
    requestFingerprint: sha256(canonicalJson(cloned)),
    request: cloned.request,
    ...(cloned.scopeIdSha256 ? { scopeIdSha256: cloned.scopeIdSha256 } : {}),
  };
}

function replayReference(
  cassette: ReplayCassette,
  relativePath: string,
): ReplayReference {
  return {
    requestFingerprint: cassette.requestFingerprint,
    occurrence: cassette.occurrence,
    relativePath,
    integritySha256: cassette.integritySha256,
    ...(cassette.scopeIdSha256
      ? { scopeIdSha256: cassette.scopeIdSha256 }
      : {}),
  };
}

function cassetteFileName(fingerprint: string, occurrence: number): string {
  if (
    !/^[a-f0-9]{64}$/u.test(fingerprint) ||
    !Number.isSafeInteger(occurrence) ||
    occurrence < 1
  ) {
    throw new Error("Replay cassette key is invalid.");
  }
  return `${fingerprint}.${String(occurrence).padStart(6, "0")}.json`;
}

async function highestRecordedOccurrence(
  root: string,
  fingerprint: string,
): Promise<number> {
  const pattern = new RegExp(
    `^${fingerprint}\\.([0-9]{6,})\\.json$`,
    "u",
  );
  let highest = 0;
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    const match = pattern.exec(entry.name);
    if (!match) {
      continue;
    }
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`Replay occurrence is not a regular file: ${entry.name}`);
    }
    const occurrence = Number(match[1]);
    if (!Number.isSafeInteger(occurrence) || occurrence < 1) {
      throw new Error(`Replay occurrence filename is invalid: ${entry.name}`);
    }
    highest = Math.max(highest, occurrence);
  }
  return highest;
}

async function readCursorChain(
  root: string,
  cursorIdSha256: string,
): Promise<ReplayCursorSnapshot | undefined> {
  const directory = path.join(root, ".replay-cursors");
  await fs.mkdir(directory, { recursive: true });
  await assertDirectoryNotSymlink(directory);
  const prefix = `${cursorIdSha256}.`;
  const paths = (await fs.readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.name.startsWith(prefix) && entry.name.endsWith(".json"))
    .map((entry) => {
      if (!entry.isFile() || entry.isSymbolicLink()) {
        throw new Error(`Replay cursor snapshot is not a regular file: ${entry.name}`);
      }
      return entry.name;
    })
    .sort();
  let previous: ReplayCursorSnapshot | undefined;
  for (const fileName of paths) {
    const snapshot = JSON.parse(
      await fs.readFile(confinedPath(directory, fileName), "utf8"),
    ) as ReplayCursorSnapshot;
    validateCursorSnapshot(snapshot, cursorIdSha256, previous);
    previous = snapshot;
  }
  return previous;
}

async function writeCursorSnapshot(
  root: string,
  cursorIdSha256: string,
  input: {
    sequence: number;
    previousDigestSha256: string | null;
    occurrences: Readonly<Record<string, number>>;
  },
): Promise<void> {
  const directory = path.join(root, ".replay-cursors");
  await fs.mkdir(directory, { recursive: true });
  await assertDirectoryNotSymlink(directory);
  const unsigned = {
    schemaVersion: 2 as const,
    cursorIdSha256,
    sequence: input.sequence,
    previousDigestSha256: input.previousDigestSha256,
    occurrences: Object.fromEntries(
      Object.entries(input.occurrences).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
  };
  const snapshot: ReplayCursorSnapshot = {
    ...unsigned,
    digestSha256: sha256(canonicalJson(unsigned)),
  };
  await writeImmutableJson(
    confinedPath(
      directory,
      `${cursorIdSha256}.${String(input.sequence).padStart(8, "0")}.json`,
    ),
    snapshot,
  );
}

function validateCursorSnapshot(
  snapshot: ReplayCursorSnapshot,
  cursorIdSha256: string,
  previous: ReplayCursorSnapshot | undefined,
): void {
  if (
    snapshot.schemaVersion !== 2 ||
    snapshot.cursorIdSha256 !== cursorIdSha256 ||
    snapshot.sequence !== (previous?.sequence ?? 0) + 1 ||
    snapshot.previousDigestSha256 !== (previous?.digestSha256 ?? null) ||
    !/^[a-f0-9]{64}$/u.test(snapshot.digestSha256)
  ) {
    throw new Error("Replay cursor snapshot schema or chain is invalid.");
  }
  for (const [fingerprint, occurrence] of Object.entries(snapshot.occurrences)) {
    if (
      !/^[a-f0-9]{64}$/u.test(fingerprint) ||
      !Number.isSafeInteger(occurrence) ||
      occurrence < 1
    ) {
      throw new Error("Replay cursor snapshot contains an invalid occurrence.");
    }
    const previousOccurrence = previous?.occurrences[fingerprint] ?? 0;
    if (occurrence < previousOccurrence) {
      throw new Error("Replay cursor occurrence moved backwards.");
    }
  }
  const { digestSha256, ...unsigned } = snapshot;
  if (digestSha256 !== sha256(canonicalJson(unsigned))) {
    throw new Error("Replay cursor snapshot integrity validation failed.");
  }
}

function confinedPath(root: string, relativePath: string): string {
  if (!relativePath || path.isAbsolute(relativePath)) {
    throw new Error("Replay paths must be non-empty relative paths.");
  }
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Replay path escapes its confined storage root.");
  }
  return resolved;
}

async function assertConfinedRegularFile(
  root: string,
  filePath: string,
): Promise<void> {
  const resolved = confinedPath(root, path.relative(root, filePath));
  const stat = await fs.lstat(resolved);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error("Replay cassette must be a regular confined file.");
  }
  const real = await fs.realpath(resolved);
  const relative = path.relative(root, real);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Replay cassette resolves outside its storage root.");
  }
}

async function assertOptionalDirectoryNotSymlink(directory: string): Promise<void> {
  try {
    await assertDirectoryNotSymlink(directory);
  } catch (error) {
    if (!isMissingFileError(error)) {
      throw error;
    }
  }
}

async function assertDirectoryNotSymlink(directory: string): Promise<void> {
  const stat = await fs.lstat(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`Replay storage path must be a real directory: ${directory}`);
  }
}

function cloneJson(value: unknown): unknown {
  return JSON.parse(prettyCanonicalJson(value)) as unknown;
}

function sanitizeReplayValue(input: unknown): {
  value: unknown;
  redacted: boolean;
  markers: string[];
} {
  const stripped = stripSecretBearingHeaders(input);
  const redacted = redactForLog(stripped.value);
  const markers = [...new Set([...stripped.markers, ...redacted.markers])].sort();
  return {
    value: redacted.value,
    redacted: markers.length > 0,
    markers,
  };
}

function stripSecretBearingHeaders(
  input: unknown,
  seen = new WeakSet<object>(),
): { value: unknown; markers: string[] } {
  if (typeof input === "string") {
    let changed = false;
    const value = input.replace(
      /((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*)([^\r\n]{4,})/giu,
      (_match, prefix: string) => {
        changed = true;
        return `${prefix}[REDACTED]`;
      },
    );
    return {
      value,
      markers: changed ? ["secret-bearing-header"] : [],
    };
  }
  if (input === null || typeof input !== "object") {
    return { value: input, markers: [] };
  }
  if (seen.has(input)) {
    return { value: "[Circular]", markers: ["circular-value"] };
  }
  seen.add(input);
  try {
    if (Array.isArray(input)) {
      const markers: string[] = [];
      const value = input.map((item) => {
        const child = stripSecretBearingHeaders(item, seen);
        markers.push(...child.markers);
        return child.value;
      });
      return { value, markers };
    }

    const output = Object.create(null) as Record<string, unknown>;
    const markers: string[] = [];
    for (const [key, value] of Object.entries(input)) {
      if (
        /^(?:headers?|authorization|proxy-authorization|cookie|set-cookie|x-api-key)$/iu.test(
          key,
        )
      ) {
        output[key] = "[REDACTED]";
        markers.push("secret-bearing-header");
        continue;
      }
      const child = stripSecretBearingHeaders(value, seen);
      output[key] = child.value;
      markers.push(...child.markers);
    }
    return { value: output, markers };
  } finally {
    seen.delete(input);
  }
}

async function readLockOwner(
  lockPath: string,
): Promise<{ token: string; pid: number; createdAt: string } | undefined> {
  try {
    const parsed = JSON.parse(
      await fs.readFile(path.join(lockPath, "owner.json"), "utf8"),
    ) as { token?: unknown; pid?: unknown; createdAt?: unknown };
    if (
      typeof parsed.token === "string" &&
      typeof parsed.pid === "number" &&
      typeof parsed.createdAt === "string"
    ) {
      return { token: parsed.token, pid: parsed.pid, createdAt: parsed.createdAt };
    }
    return undefined;
  } catch (error) {
    if (isMissingFileError(error) || error instanceof SyntaxError) {
      return undefined;
    }
    throw error;
  }
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isNodeError(error) && error.code === "EPERM";
  }
}

function samePath(left: string, right: string): boolean {
  return process.platform === "win32"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function isFileExistsError(error: unknown): boolean {
  return isNodeError(error) && error.code === "EEXIST";
}

function isRetryableLockContentionError(error: unknown): boolean {
  if (isFileExistsError(error)) {
    return true;
  }
  return isRetryableWindowsLockError(error);
}

function isRetryableWindowsLockError(error: unknown): boolean {
  return (
    process.platform === "win32" &&
    isNodeError(error) &&
    (error.code === "EPERM" || error.code === "EBUSY")
  );
}

function isMissingFileError(error: unknown): boolean {
  return isNodeError(error) && error.code === "ENOENT";
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
