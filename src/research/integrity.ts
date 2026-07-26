import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeForJson(value));
}

export function prettyCanonicalJson(value: unknown): string {
  return `${JSON.stringify(normalizeForJson(value), null, 2)}\n`;
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export async function sha256File(filePath: string): Promise<{ sha256: string; bytes: number }> {
  const content = await fs.readFile(filePath);
  return {
    sha256: sha256(content),
    bytes: content.byteLength,
  };
}

export async function writeImmutableJson(filePath: string, value: unknown): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true });
  const tempPath = path.join(
    directory,
    `.${path.basename(filePath)}.hermsec-tmp-${randomUUID()}`,
  );
  const handle = await fs.open(tempPath, "wx");
  try {
    await handle.writeFile(prettyCanonicalJson(value), "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    // A same-volume hard link publishes the fully synced temp file without
    // replacing an existing immutable destination.
    await fs.link(tempPath, filePath);
    await syncDirectory(directory);
  } finally {
    await fs.rm(tempPath, { force: true });
  }
}

export async function recoverImmutableJsonTemps(directory: string): Promise<number> {
  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return 0;
    }
    throw error;
  }
  let recovered = 0;
  for (const entry of entries) {
    if (
      !entry.name.startsWith(".") ||
      !/\.hermsec-tmp-[a-f0-9-]{36}$/u.test(entry.name)
    ) {
      continue;
    }
    const candidate = path.join(directory, entry.name);
    const stat = await fs.lstat(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`Refusing to recover a non-file immutable temp path: ${candidate}`);
    }
    await fs.rm(candidate);
    recovered += 1;
  }
  if (recovered > 0) {
    await syncDirectory(directory);
  }
  return recovered;
}

export function assertSafeArtifactPath(runDirectory: string, relativePath: string): string {
  if (!relativePath || path.isAbsolute(relativePath)) {
    throw new Error("Artifact paths must be non-empty paths relative to the run directory.");
  }

  const root = path.resolve(runDirectory);
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`Artifact path escapes the run directory: ${relativePath}`);
  }
  return resolved;
}

function normalizeForJson(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Canonical JSON does not support non-finite numbers.");
    }
    return value;
  }
  if (typeof value === "bigint" || typeof value === "function" || typeof value === "symbol") {
    throw new Error(`Canonical JSON does not support ${typeof value} values.`);
  }
  if (value === undefined) {
    return undefined;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Buffer.isBuffer(value)) {
    return { type: "Buffer", data: value.toString("base64") };
  }
  if (typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    throw new Error("Canonical JSON does not support circular values.");
  }
  seen.add(value);

  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizeForJson(item, seen) ?? null);
    }

    const output = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value).sort()) {
      const normalized = normalizeForJson((value as Record<string, unknown>)[key], seen);
      if (normalized !== undefined) {
        output[key] = normalized;
      }
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

async function syncDirectory(directory: string): Promise<void> {
  let handle;
  try {
    handle = await fs.open(directory, "r");
    await handle.sync();
  } catch (error) {
    // Windows may reject syncing directory handles. The file itself was fsynced
    // before publication, and the hard-link operation remains atomic.
    if (process.platform !== "win32") {
      throw error;
    }
  } finally {
    await handle?.close();
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
