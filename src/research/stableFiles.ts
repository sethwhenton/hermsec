import { createHash } from "node:crypto";
import {
  constants as fsConstants,
  type BigIntStats,
} from "node:fs";
import fs, { type FileHandle } from "node:fs/promises";
import path from "node:path";

export type StableFileDigest = {
  path: string;
  bytes: number;
  sha256: string;
};

export type StableTreeIdentity = {
  path: string;
  kind: "directory" | "file";
  identity: string;
};

export type StableTreeSnapshot = {
  files: readonly StableFileDigest[];
  identities: readonly StableTreeIdentity[];
  totalBytes: number;
};

export type StableTreeLimits = {
  maxDepth: number;
  maxDirectories: number;
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
};

export type StableFileRead = StableFileDigest & {
  content: Buffer;
  identity: string;
};

type RootContext = {
  resolved: string;
  real: string;
};

type EnumeratedEntry = StableTreeIdentity & {
  absolutePath: string;
};

const DEFAULT_FILE_BYTES = 64 * 1024 * 1024;

export async function readStableConfinedFile(
  rootDirectory: string,
  relativePath: string,
  options: {
    maxBytes?: number;
    expectedIdentity?: string;
  } = {},
): Promise<StableFileRead> {
  const root = await resolveRoot(rootDirectory);
  const canonicalPath = canonicalRelativePath(relativePath);
  const absolutePath = path.resolve(
    root.resolved,
    ...canonicalPath.split("/"),
  );
  assertLexicallyInside(root.resolved, absolutePath);
  await assertUnlinkedParents(root, absolutePath);

  const before = await lstatBigInt(absolutePath);
  assertRegularSingleLink(before, canonicalPath);
  const beforeIdentity = statIdentity(before);
  if (
    options.expectedIdentity !== undefined &&
    beforeIdentity !== options.expectedIdentity
  ) {
    throw new Error(
      `Stable file identity changed before read: ${canonicalPath}`,
    );
  }
  const beforeRealPath = await fs.realpath(absolutePath);
  assertRealInside(root.real, beforeRealPath);

  const handle = await openReadOnlyNoFollow(absolutePath);
  try {
    const opened = await handle.stat({ bigint: true });
    assertRegularSingleLink(opened, canonicalPath);
    if (statIdentity(opened) !== beforeIdentity) {
      throw new Error(
        `Stable file identity changed while opening: ${canonicalPath}`,
      );
    }

    const maxBytes = boundedPositiveInteger(
      options.maxBytes,
      DEFAULT_FILE_BYTES,
      "stable file byte limit",
    );
    if (
      opened.size > BigInt(maxBytes) ||
      opened.size > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      throw new Error(
        `Stable file exceeds the ${maxBytes}-byte limit: ${canonicalPath}`,
      );
    }
    const expectedBytes = Number(opened.size);
    const content = await readExact(handle, expectedBytes, canonicalPath);

    const afterHandle = await handle.stat({ bigint: true });
    assertRegularSingleLink(afterHandle, canonicalPath);
    if (statIdentity(afterHandle) !== beforeIdentity) {
      throw new Error(
        `Stable file identity changed during read: ${canonicalPath}`,
      );
    }

    const afterPath = await lstatBigInt(absolutePath);
    assertRegularSingleLink(afterPath, canonicalPath);
    if (statIdentity(afterPath) !== beforeIdentity) {
      throw new Error(
        `Stable file path changed during read: ${canonicalPath}`,
      );
    }
    const afterRealPath = await fs.realpath(absolutePath);
    assertRealInside(root.real, afterRealPath);
    if (!samePath(beforeRealPath, afterRealPath)) {
      throw new Error(
        `Stable file real path changed during read: ${canonicalPath}`,
      );
    }

    return {
      path: canonicalPath,
      bytes: content.byteLength,
      sha256: createHash("sha256").update(content).digest("hex"),
      content,
      identity: beforeIdentity,
    };
  } finally {
    await handle.close();
  }
}

export async function hashStableConfinedFile(
  rootDirectory: string,
  relativePath: string,
  options: {
    maxBytes?: number;
    expectedIdentity?: string;
  } = {},
): Promise<StableFileDigest> {
  const { content: _content, identity: _identity, ...digest } =
    await readStableConfinedFile(rootDirectory, relativePath, options);
  return digest;
}

export async function captureStableTree(
  rootDirectory: string,
  limits: StableTreeLimits,
): Promise<StableTreeSnapshot> {
  validateTreeLimits(limits);
  const first = await enumerateStableTree(rootDirectory, limits);
  const files: StableFileDigest[] = [];
  let totalBytes = 0;

  for (const entry of first.filter(
    (candidate) => candidate.kind === "file",
  )) {
    const file = await readStableConfinedFile(
      rootDirectory,
      entry.path,
      {
        maxBytes: limits.maxFileBytes,
        expectedIdentity: entry.identity,
      },
    );
    totalBytes += file.bytes;
    if (totalBytes > limits.maxTotalBytes) {
      throw new Error(
        `Stable tree exceeds the ${limits.maxTotalBytes}-byte total limit.`,
      );
    }
    files.push({
      path: file.path,
      bytes: file.bytes,
      sha256: file.sha256,
    });
  }

  const second = await enumerateStableTree(rootDirectory, limits);
  if (identitySet(first) !== identitySet(second)) {
    throw new Error("Stable tree changed while it was being captured.");
  }

  return {
    files: files.sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    identities: first.map(({ absolutePath: _absolutePath, ...entry }) =>
      entry
    ),
    totalBytes,
  };
}

export async function listStableTreeFiles(
  rootDirectory: string,
  limits: Pick<
    StableTreeLimits,
    "maxDepth" | "maxDirectories" | "maxFiles"
  >,
): Promise<string[]> {
  const resolvedLimits = {
    ...limits,
    maxFileBytes: Number.MAX_SAFE_INTEGER,
    maxTotalBytes: Number.MAX_SAFE_INTEGER,
  };
  const first = await enumerateStableTree(
    rootDirectory,
    resolvedLimits,
  );
  const second = await enumerateStableTree(
    rootDirectory,
    resolvedLimits,
  );
  if (identitySet(first) !== identitySet(second)) {
    throw new Error(
      "Stable tree changed while its file inventory was being captured.",
    );
  }
  return first
    .filter((entry) => entry.kind === "file")
    .map((entry) => entry.path)
    .sort();
}

export async function inspectStableTreeEntry(
  rootDirectory: string,
  relativePath: string,
): Promise<StableTreeIdentity> {
  const root = await resolveRoot(rootDirectory);
  const canonicalPath =
    relativePath === "." ? "." : canonicalRelativePath(relativePath);
  const absolutePath =
    canonicalPath === "."
      ? root.resolved
      : path.resolve(root.resolved, ...canonicalPath.split("/"));
  assertLexicallyInside(root.resolved, absolutePath);
  if (canonicalPath !== ".") {
    await assertUnlinkedParents(root, absolutePath);
  }
  const before = await lstatBigInt(absolutePath);
  const kind = stableEntryKind(before, canonicalPath);
  const beforeIdentity = statIdentity(before);
  const beforeRealPath = await fs.realpath(absolutePath);
  assertRealInside(root.real, beforeRealPath);
  const after = await lstatBigInt(absolutePath);
  if (
    stableEntryKind(after, canonicalPath) !== kind ||
    statIdentity(after) !== beforeIdentity
  ) {
    throw new Error(
      `Stable tree entry changed during inspection: ${canonicalPath}`,
    );
  }
  const afterRealPath = await fs.realpath(absolutePath);
  assertRealInside(root.real, afterRealPath);
  if (!samePath(beforeRealPath, afterRealPath)) {
    throw new Error(
      `Stable tree entry real path changed during inspection: ${canonicalPath}`,
    );
  }
  return {
    path: canonicalPath,
    kind,
    identity: beforeIdentity,
  };
}

export function stableObjectIdentity(identity: string): string {
  const fields = identity.split(":");
  if (fields.length !== 7 || fields.some((field) => !/^\d+$/u.test(field))) {
    throw new Error("Stable tree identity is malformed.");
  }
  return `${fields[0]}:${fields[1]}`;
}

async function enumerateStableTree(
  rootDirectory: string,
  limits: StableTreeLimits,
): Promise<EnumeratedEntry[]> {
  validateTreeLimits(limits);
  const root = await resolveRoot(rootDirectory);
  const rootStat = await lstatBigInt(root.resolved);
  const entries: EnumeratedEntry[] = [
    {
      path: ".",
      kind: "directory",
      identity: statIdentity(rootStat),
      absolutePath: root.resolved,
    },
  ];
  const pending: Array<{
    absolutePath: string;
    relativePath: string;
    depth: number;
  }> = [
    {
      absolutePath: root.resolved,
      relativePath: ".",
      depth: 0,
    },
  ];
  const seenPaths = new Set<string>([pathKey(".")]);
  let directoryCount = 1;
  let fileCount = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) {
      continue;
    }
    const before = await lstatBigInt(current.absolutePath);
    assertDirectory(before, current.relativePath);
    const beforeIdentity = statIdentity(before);
    const currentRealPath = await fs.realpath(current.absolutePath);
    assertRealInside(root.real, currentRealPath);

    const children = await fs.readdir(current.absolutePath, {
      withFileTypes: true,
    });
    const after = await lstatBigInt(current.absolutePath);
    assertDirectory(after, current.relativePath);
    if (statIdentity(after) !== beforeIdentity) {
      throw new Error(
        `Stable directory changed during enumeration: ${current.relativePath}`,
      );
    }
    const afterRealPath = await fs.realpath(current.absolutePath);
    assertRealInside(root.real, afterRealPath);
    if (!samePath(currentRealPath, afterRealPath)) {
      throw new Error(
        `Stable directory real path changed during enumeration: ${current.relativePath}`,
      );
    }

    for (const child of children.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      const relativePath = canonicalRelativePath(
        current.relativePath === "."
          ? child.name
          : `${current.relativePath}/${child.name}`,
      );
      const key = pathKey(relativePath);
      if (seenPaths.has(key)) {
        throw new Error(
          `Stable tree contains a duplicate path: ${relativePath}`,
        );
      }
      seenPaths.add(key);
      const absolutePath = path.join(current.absolutePath, child.name);
      assertLexicallyInside(root.resolved, absolutePath);
      const childBefore = await lstatBigInt(absolutePath);
      if (childBefore.isSymbolicLink()) {
        throw new Error(
          `Stable tree cannot contain a symbolic link or junction: ${relativePath}`,
        );
      }
      const childRealPath = await fs.realpath(absolutePath);
      assertRealInside(root.real, childRealPath);
      const childAfter = await lstatBigInt(absolutePath);
      if (statIdentity(childAfter) !== statIdentity(childBefore)) {
        throw new Error(
          `Stable tree path changed during enumeration: ${relativePath}`,
        );
      }

      if (childBefore.isDirectory()) {
        const depth = current.depth + 1;
        if (depth > limits.maxDepth) {
          throw new Error(
            `Stable tree exceeds the ${limits.maxDepth}-level depth limit.`,
          );
        }
        directoryCount += 1;
        if (directoryCount > limits.maxDirectories) {
          throw new Error(
            `Stable tree exceeds the ${limits.maxDirectories}-directory limit.`,
          );
        }
        entries.push({
          path: relativePath,
          kind: "directory",
          identity: statIdentity(childBefore),
          absolutePath,
        });
        pending.push({
          absolutePath,
          relativePath,
          depth,
        });
        continue;
      }
      if (childBefore.isFile()) {
        assertRegularSingleLink(childBefore, relativePath);
        fileCount += 1;
        if (fileCount > limits.maxFiles) {
          throw new Error(
            `Stable tree exceeds the ${limits.maxFiles}-file limit.`,
          );
        }
        entries.push({
          path: relativePath,
          kind: "file",
          identity: statIdentity(childBefore),
          absolutePath,
        });
        continue;
      }
      throw new Error(
        `Stable tree contains a special file: ${relativePath}`,
      );
    }
  }

  return entries.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.kind.localeCompare(right.kind),
  );
}

async function resolveRoot(rootDirectory: string): Promise<RootContext> {
  const resolved = path.resolve(rootDirectory);
  const before = await lstatBigInt(resolved);
  assertDirectory(before, ".");
  const beforeIdentity = statIdentity(before);
  const real = await fs.realpath(resolved);
  const after = await lstatBigInt(resolved);
  assertDirectory(after, ".");
  if (statIdentity(after) !== beforeIdentity) {
    throw new Error("Stable root directory changed during resolution.");
  }
  return { resolved, real };
}

async function assertUnlinkedParents(
  root: RootContext,
  absolutePath: string,
): Promise<void> {
  const relative = path.relative(root.resolved, absolutePath);
  const segments = relative.split(path.sep).filter(Boolean);
  let current = root.resolved;
  for (const segment of segments.slice(0, -1)) {
    current = path.join(current, segment);
    const before = await lstatBigInt(current);
    assertDirectory(before, path.relative(root.resolved, current) || ".");
    const beforeIdentity = statIdentity(before);
    const real = await fs.realpath(current);
    assertRealInside(root.real, real);
    const after = await lstatBigInt(current);
    if (statIdentity(after) !== beforeIdentity) {
      throw new Error(
        `Stable parent directory changed: ${path.relative(
          root.resolved,
          current,
        )}`,
      );
    }
  }
}

async function openReadOnlyNoFollow(
  filePath: string,
): Promise<FileHandle> {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow === "number" && noFollow !== 0) {
    try {
      return await fs.open(
        filePath,
        fsConstants.O_RDONLY | noFollow,
      );
    } catch (error) {
      if (
        process.platform !== "win32" ||
        !isNodeError(error, "EINVAL", "ENOTSUP", "UNKNOWN")
      ) {
        throw error;
      }
    }
  }
  return fs.open(filePath, fsConstants.O_RDONLY);
}

async function readExact(
  handle: FileHandle,
  expectedBytes: number,
  relativePath: string,
): Promise<Buffer> {
  const content = Buffer.alloc(expectedBytes);
  let offset = 0;
  while (offset < expectedBytes) {
    const result = await handle.read(
      content,
      offset,
      expectedBytes - offset,
      offset,
    );
    if (result.bytesRead === 0) {
      throw new Error(
        `Stable file was truncated during read: ${relativePath}`,
      );
    }
    offset += result.bytesRead;
  }
  const extra = Buffer.alloc(1);
  const tail = await handle.read(extra, 0, 1, expectedBytes);
  if (tail.bytesRead !== 0) {
    throw new Error(
      `Stable file grew during read: ${relativePath}`,
    );
  }
  return content;
}

async function lstatBigInt(filePath: string): Promise<BigIntStats> {
  return fs.lstat(filePath, { bigint: true });
}

function assertDirectory(
  stat: BigIntStats,
  relativePath: string,
): void {
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(
      `Stable tree requires a real directory: ${relativePath}`,
    );
  }
}

function assertRegularSingleLink(
  stat: BigIntStats,
  relativePath: string,
): void {
  if (
    stat.isSymbolicLink() ||
    !stat.isFile() ||
    stat.nlink !== 1n
  ) {
    throw new Error(
      `Stable files must be regular single-link files: ${relativePath}`,
    );
  }
}

function stableEntryKind(
  stat: BigIntStats,
  relativePath: string,
): StableTreeIdentity["kind"] {
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    return "directory";
  }
  assertRegularSingleLink(stat, relativePath);
  return "file";
}

function statIdentity(stat: BigIntStats): string {
  return [
    stat.dev,
    stat.ino,
    stat.mode,
    stat.nlink,
    stat.size,
    stat.mtimeNs,
    stat.ctimeNs,
  ].join(":");
}

function identitySet(entries: readonly EnumeratedEntry[]): string {
  return entries
    .map((entry) => `${entry.kind}\u0000${entry.path}\u0000${entry.identity}`)
    .join("\n");
}

function canonicalRelativePath(relativePath: string): string {
  if (
    typeof relativePath !== "string" ||
    relativePath.includes("\0") ||
    path.isAbsolute(relativePath) ||
    path.win32.isAbsolute(relativePath) ||
    path.posix.isAbsolute(relativePath)
  ) {
    throw new Error("Stable file paths must be relative.");
  }
  const normalized = path.posix.normalize(
    relativePath.replaceAll("\\", "/"),
  );
  if (
    !normalized ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    throw new Error("Stable file path escapes its root.");
  }
  return normalized;
}

function assertLexicallyInside(root: string, candidate: string): void {
  const relative = path.relative(root, path.resolve(candidate));
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Stable path escapes its lexical root.");
  }
}

function assertRealInside(rootReal: string, candidateReal: string): void {
  const relative = path.relative(rootReal, candidateReal);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Stable path resolves outside its real root.");
  }
}

function samePath(left: string, right: string): boolean {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function pathKey(relativePath: string): string {
  return process.platform === "win32"
    ? relativePath.toLowerCase()
    : relativePath;
}

function validateTreeLimits(limits: StableTreeLimits): void {
  for (const [label, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`Stable tree ${label} must be a positive integer.`);
    }
  }
}

function boundedPositiveInteger(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return resolved;
}

function isNodeError(
  error: unknown,
  ...codes: string[]
): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    typeof (error as NodeJS.ErrnoException).code === "string" &&
    codes.includes((error as NodeJS.ErrnoException).code!)
  );
}
