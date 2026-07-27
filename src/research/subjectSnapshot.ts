import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import {
  constants as fsConstants,
  type BigIntStats,
} from "node:fs";
import fs, { type FileHandle } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ValidatedFixtureLayout } from "../eval/fixtureLayout.js";
import { canonicalJson } from "./integrity.js";
import {
  captureStableTree,
  readStableConfinedFile,
  stableObjectIdentity,
  type StableTreeLimits,
  type StableTreeIdentity,
  type StableTreeSnapshot,
} from "./stableFiles.js";

export type SubjectSnapshotWorkspace = {
  root: string;
  parent: string;
  device: string;
  inode: string;
  identity: string;
  parentDevice: string;
  parentInode: string;
  parentIdentity: string;
  cleanupInventory?: readonly StableTreeIdentity[];
};

export type MaterializedFixtureSnapshots = {
  subjectRoot: string;
  evaluatorRoot: string;
  subjectSnapshot: StableTreeSnapshot;
  evaluatorSnapshot: StableTreeSnapshot;
};

const WORKSPACE_PREFIX = "hermsec-subjects-";
export async function createSubjectSnapshotWorkspace(): Promise<SubjectSnapshotWorkspace> {
  const parent = await fs.realpath(os.tmpdir());
  const parentStat = await fs.lstat(parent, { bigint: true });
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw new Error(
      "Research subject snapshot parent is not a real directory.",
    );
  }
  const root = await fs.mkdtemp(path.join(parent, WORKSPACE_PREFIX));
  await fs.chmod(root, 0o700);
  const stat = await fs.lstat(root, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(
      "Research subject snapshot workspace is not a real directory.",
    );
  }
  return {
    root,
    parent,
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    identity: statIdentity(stat),
    parentDevice: parentStat.dev.toString(),
    parentInode: parentStat.ino.toString(),
    parentIdentity: statIdentity(parentStat),
  };
}

export async function materializeFixtureSnapshots(input: {
  workspace: SubjectSnapshotWorkspace;
  sourceRoot: string;
  sourceSnapshot: StableTreeSnapshot;
  layout: ValidatedFixtureLayout;
  opaqueId: string;
  limits: StableTreeLimits;
}): Promise<MaterializedFixtureSnapshots> {
  assertOpaqueId(input.opaqueId);
  await assertWorkspaceIdentity(input.workspace);
  const fixtureRoot = path.join(input.workspace.root, input.opaqueId);
  const subjectRoot = path.join(fixtureRoot, "subject");
  const evaluatorRoot = path.join(fixtureRoot, "evaluator");
  await fs.mkdir(subjectRoot, { recursive: true, mode: 0o700 });
  await fs.mkdir(evaluatorRoot, { recursive: true, mode: 0o700 });

  const identities = new Map(
    input.sourceSnapshot.identities
      .filter((entry) => entry.kind === "file")
      .map((entry) => [entry.path, entry.identity] as const),
  );
  const projectPathByFixturePath = new Map(
    input.layout.projectFiles.map((file) => [
      file.fixturePath,
      file.projectPath,
    ]),
  );
  const expectedSubjectFiles = input.sourceSnapshot.files
    .filter((file) => projectPathByFixturePath.has(file.path))
    .map((file) => ({
      ...file,
      path: projectPathByFixturePath.get(file.path)!,
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  if (expectedSubjectFiles.length === 0) {
    throw new Error(
      "Research subject snapshot cannot be empty after control-file exclusion.",
    );
  }

  for (const sourceFile of input.sourceSnapshot.files) {
    const expectedIdentity = identities.get(sourceFile.path);
    if (!expectedIdentity) {
      throw new Error(
        `Research source identity is missing for ${sourceFile.path}.`,
      );
    }
    const stableFile = await readStableConfinedFile(
      input.sourceRoot,
      sourceFile.path,
      {
        maxBytes: input.limits.maxFileBytes,
        expectedIdentity,
      },
    );
    if (
      stableFile.bytes !== sourceFile.bytes ||
      stableFile.sha256 !== sourceFile.sha256
    ) {
      throw new Error(
        `Research source changed while materializing ${sourceFile.path}.`,
      );
    }
    await writeSnapshotFile(
      evaluatorRoot,
      sourceFile.path,
      stableFile.content,
    );
    const projectPath = projectPathByFixturePath.get(sourceFile.path);
    if (projectPath) {
      await writeSnapshotFile(
        subjectRoot,
        projectPath,
        stableFile.content,
      );
    }
  }

  const evaluatorSnapshot = await hardenAndCapture(
    evaluatorRoot,
    input.limits,
  );
  const subjectSnapshot = await hardenAndCapture(
    subjectRoot,
    input.limits,
  );
  assertFileRecordsEqual(
    evaluatorSnapshot.files,
    input.sourceSnapshot.files,
    "full evaluator snapshot",
  );
  assertFileRecordsEqual(
    subjectSnapshot.files,
    expectedSubjectFiles,
    "project-only subject snapshot",
  );
  await assertWorkspaceIdentity(input.workspace);
  return {
    subjectRoot,
    evaluatorRoot,
    subjectSnapshot,
    evaluatorSnapshot,
  };
}

export async function sealSubjectSnapshotWorkspace(
  workspace: SubjectSnapshotWorkspace,
  limits: StableTreeLimits,
): Promise<void> {
  await assertWorkspaceIdentity(workspace);
  if (workspace.cleanupInventory) {
    throw new Error("Research subject snapshot workspace is already sealed.");
  }
  workspace.cleanupInventory = (
    await captureStableTree(workspace.root, limits)
  ).identities;
}

export async function removeSubjectSnapshotWorkspace(
  workspace: SubjectSnapshotWorkspace,
  options: {
    /**
     * Retained for source compatibility. Cleanup never recaptures the tree:
     * only the inventory sealed before detector execution is authoritative.
     */
    limits?: StableTreeLimits;
    beforeRemoveEntry?: (
      relativePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterTombstoneInspection?: (
      relativePath: string,
      tombstonePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterFinalTombstoneInspection?: (
      relativePath: string,
      finalTombstonePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterRootInspection?: (
      cleanupRoot: string,
      phase: "quarantined" | "before-remove",
    ) => void | Promise<void>;
  } = {},
): Promise<void> {
  void options.limits;
  const quarantine = await quarantineWorkspace(workspace);
  const inventory = workspace.cleanupInventory;
  if (!inventory) {
    throw new Error(
      `Research subject snapshot workspace was not sealed; cleanup quarantined it at ${quarantine}.`,
    );
  }
  await removeCapturedTree(
    quarantine,
    inventory,
    {
      path: workspace.parent,
      identity: workspace.parentIdentity,
    },
    options,
  );
}

async function hardenAndCapture(
  root: string,
  limits: StableTreeLimits,
): Promise<StableTreeSnapshot> {
  return captureStableTree(root, limits);
}

async function writeSnapshotFile(
  root: string,
  relativePath: string,
  content: Buffer,
): Promise<void> {
  const normalized = normalizeRelative(relativePath);
  const absolutePath = path.resolve(
    root,
    ...normalized.split("/"),
  );
  assertInside(root, absolutePath);
  await fs.mkdir(path.dirname(absolutePath), {
    recursive: true,
    mode: 0o700,
  });
  // The descriptor remains writable for initial publication, while the
  // resulting path is read-only. Directories stay private and writable so
  // cleanup never needs permission-changing operations.
  const handle = await fs.open(absolutePath, "wx", 0o400);
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertWorkspaceIdentity(
  workspace: SubjectSnapshotWorkspace,
): Promise<void> {
  assertDirectChild(workspace.parent, workspace.root);
  if (!path.basename(workspace.root).startsWith(WORKSPACE_PREFIX)) {
    throw new Error(
      "Research subject snapshot workspace name is invalid.",
    );
  }
  const stat = await fs.lstat(workspace.root, { bigint: true });
  if (
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.dev.toString() !== workspace.device ||
    stat.ino.toString() !== workspace.inode
  ) {
    throw new Error(
      "Research subject snapshot workspace identity changed.",
    );
  }
  const real = await fs.realpath(workspace.root);
  if (!samePath(real, workspace.root)) {
    throw new Error(
      "Research subject snapshot workspace real path changed.",
    );
  }
}

async function removeCapturedTree(
  root: string,
  inventory: readonly StableTreeIdentity[],
  trustedParent: {
    path: string;
    identity: string;
  },
  options: {
    beforeRemoveEntry?: (
      relativePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterTombstoneInspection?: (
      relativePath: string,
      tombstonePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterFinalTombstoneInspection?: (
      relativePath: string,
      finalTombstonePath: string,
      cleanupRoot: string,
    ) => void | Promise<void>;
    afterRootInspection?: (
      cleanupRoot: string,
      phase: "quarantined" | "before-remove",
    ) => void | Promise<void>;
  },
): Promise<void> {
  const byPath = validateCleanupInventory(inventory);
  const expectedRoot = byPath.get(".")!;
  const expectedTrustedParent: StableTreeIdentity = {
    path: ".",
    kind: "directory",
    identity: trustedParent.identity,
  };
  const trustedParentHandle = await openCleanupWitness(
    trustedParent.path,
    expectedTrustedParent,
  );
  let rootHandle: FileHandle | undefined;
  try {
    rootHandle = await openCleanupWitness(root, expectedRoot);
    await options.afterRootInspection?.(root, "quarantined");
    await assertWitnessAtPath(root, rootHandle, expectedRoot);

    const entries = inventory
      .filter((entry) => entry.path !== ".")
      .sort(
        (left, right) =>
          right.path.split("/").length -
            left.path.split("/").length ||
          (left.kind === right.kind
            ? right.path.localeCompare(left.path)
            : left.kind === "file"
              ? -1
              : 1),
      );

    for (const entry of entries) {
      await assertWitnessAtPath(root, rootHandle, expectedRoot);
      const parentRelative = cleanupParentPath(entry.path);
      const expectedParent = byPath.get(parentRelative);
      if (!expectedParent || expectedParent.kind !== "directory") {
        throw new Error(
          `Research cleanup parent is absent from inventory: ${entry.path}`,
        );
      }
      const absoluteParent = cleanupAbsolutePath(root, parentRelative);
      const absoluteEntry = cleanupAbsolutePath(root, entry.path);
      const parentHandle = await openCleanupWitness(
        absoluteParent,
        expectedParent,
      );
      const entryHandle = await openCleanupWitness(
        absoluteEntry,
        entry,
        { exactIdentity: entry.kind === "file" },
      );
      try {
        await options.beforeRemoveEntry?.(entry.path, root);
        await assertWitnessAtPath(root, rootHandle, expectedRoot);
        await assertWitnessAtPath(
          absoluteParent,
          parentHandle,
          expectedParent,
        );
        await assertWitnessAtPath(
          absoluteEntry,
          entryHandle,
          entry,
          entry.kind === "file",
        );

        const tombstone = path.join(
          absoluteParent,
          `.${path.basename(absoluteEntry)}.delete-${randomUUID()}`,
        );
        assertInside(root, tombstone);
        await assertPathAbsent(tombstone);
        await fs.rename(absoluteEntry, tombstone);
        await assertPathAbsent(absoluteEntry);
        await assertWitnessAtPath(tombstone, entryHandle, entry);
        const tombstoneIdentity = statIdentity(
          await entryHandle.stat({ bigint: true }),
        );
        await assertWitnessAtPath(root, rootHandle, expectedRoot);
        await assertWitnessAtPath(
          absoluteParent,
          parentHandle,
          expectedParent,
        );
        await assertWitnessAtPath(
          tombstone,
          entryHandle,
          entry,
          true,
          tombstoneIdentity,
        );
        const deletionTombstone = path.join(
          trustedParent.path,
          `.${WORKSPACE_PREFIX}entry-${randomUUID()}`,
        );
        assertDirectChild(trustedParent.path, deletionTombstone);
        await assertWitnessAtPath(
          trustedParent.path,
          trustedParentHandle,
          expectedTrustedParent,
        );
        await assertPathAbsent(deletionTombstone);
        await fs.rename(tombstone, deletionTombstone);
        await assertPathAbsent(tombstone);
        await assertWitnessAtPath(
          deletionTombstone,
          entryHandle,
          entry,
        );
        const deletionIdentity = statIdentity(
          await entryHandle.stat({ bigint: true }),
        );
        await assertWitnessAtPath(
          trustedParent.path,
          trustedParentHandle,
          expectedTrustedParent,
        );
        await assertWitnessAtPath(
          deletionTombstone,
          entryHandle,
          entry,
          true,
          deletionIdentity,
        );
        await removeWitnessedEntry(
          deletionTombstone,
          entry,
          entryHandle,
          () =>
            options.afterTombstoneInspection?.(
              entry.path,
              deletionTombstone,
              root,
            ),
          (finalTombstone) =>
            options.afterFinalTombstoneInspection?.(
              entry.path,
              finalTombstone,
              root,
            ),
        );
      } finally {
        await entryHandle.close();
        await parentHandle.close();
      }
    }

    await assertWitnessAtPath(root, rootHandle, expectedRoot);
    await removeWitnessedEntry(
      root,
      expectedRoot,
      rootHandle,
      () => options.afterRootInspection?.(root, "before-remove"),
      (finalTombstone) =>
        options.afterFinalTombstoneInspection?.(
          ".",
          finalTombstone,
          root,
        ),
    );
  } finally {
    await rootHandle?.close();
    await trustedParentHandle.close();
  }
}

async function quarantineWorkspace(
  workspace: SubjectSnapshotWorkspace,
): Promise<string> {
  assertDirectChild(workspace.parent, workspace.root);
  if (!path.basename(workspace.root).startsWith(WORKSPACE_PREFIX)) {
    throw new Error(
      "Research subject snapshot workspace name is invalid.",
    );
  }
  const parentExpected: StableTreeIdentity = {
    path: ".",
    kind: "directory",
    identity: workspace.parentIdentity,
  };
  const rootExpected: StableTreeIdentity = {
    path: ".",
    kind: "directory",
    identity: workspace.identity,
  };
  const parentHandle = await openCleanupWitness(
    workspace.parent,
    parentExpected,
  );
  let rootHandle: FileHandle | undefined;
  const quarantine = path.join(
    workspace.parent,
    `.${WORKSPACE_PREFIX}cleanup-${randomUUID()}`,
  );
  assertDirectChild(workspace.parent, quarantine);
  try {
    rootHandle = await openCleanupWitness(
      workspace.root,
      rootExpected,
    );
    await assertPathAbsent(quarantine);
    await fs.rename(workspace.root, quarantine);
    await assertPathAbsent(workspace.root);
    await assertWitnessAtPath(
      workspace.parent,
      parentHandle,
      parentExpected,
    );
    await assertWitnessAtPath(
      quarantine,
      rootHandle,
      rootExpected,
    );
    return quarantine;
  } finally {
    await rootHandle?.close();
    await parentHandle.close();
  }
}

function validateCleanupInventory(
  inventory: readonly StableTreeIdentity[],
): Map<string, StableTreeIdentity> {
  const byPath = new Map<string, StableTreeIdentity>();
  const pathAliases = new Set<string>();
  for (const entry of inventory) {
    const normalized =
      entry.path === "." ? "." : normalizeRelative(entry.path);
    if (normalized !== entry.path) {
      throw new Error(
        `Research cleanup inventory path is not canonical: ${entry.path}`,
      );
    }
    const alias = normalized.toLowerCase();
    if (byPath.has(normalized) || pathAliases.has(alias)) {
      throw new Error(
        `Research cleanup inventory contains a duplicate path: ${entry.path}`,
      );
    }
    if (entry.kind !== "directory" && entry.kind !== "file") {
      throw new Error("Research cleanup inventory kind is invalid.");
    }
    stableObjectIdentity(entry.identity);
    byPath.set(normalized, entry);
    pathAliases.add(alias);
  }
  if (
    byPath.size !== inventory.length ||
    byPath.get(".")?.kind !== "directory"
  ) {
    throw new Error("Research cleanup inventory is invalid.");
  }
  for (const entry of inventory) {
    if (entry.path === ".") {
      continue;
    }
    const parent = byPath.get(cleanupParentPath(entry.path));
    if (!parent || parent.kind !== "directory") {
      throw new Error(
        `Research cleanup parent is absent from inventory: ${entry.path}`,
      );
    }
  }
  return byPath;
}

async function openCleanupWitness(
  absolutePath: string,
  expected: StableTreeIdentity,
  options: {
    exactIdentity?: boolean;
    identity?: string;
  } = {},
): Promise<FileHandle> {
  const before = await fs.lstat(absolutePath, { bigint: true });
  assertCleanupStat(before, expected, options);
  const handle = await openNoFollow(absolutePath);
  try {
    const opened = await handle.stat({ bigint: true });
    assertCleanupStat(opened, expected, options);
    if (objectIdentity(opened) !== objectIdentity(before)) {
      throw new Error(
        `Research cleanup path changed while opening: ${expected.path}`,
      );
    }
    const after = await fs.lstat(absolutePath, { bigint: true });
    assertCleanupStat(after, expected, options);
    if (objectIdentity(after) !== objectIdentity(before)) {
      throw new Error(
        `Research cleanup path changed during inspection: ${expected.path}`,
      );
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertWitnessAtPath(
  absolutePath: string,
  witness: FileHandle,
  expected: StableTreeIdentity,
  exactIdentity = false,
  identity?: string,
): Promise<void> {
  const expectedIdentity =
    identity ??
    (exactIdentity
      ? statIdentity(await witness.stat({ bigint: true }))
      : undefined);
  const witnessStat = await witness.stat({ bigint: true });
  const identityOptions =
    expectedIdentity === undefined
      ? { exactIdentity }
      : { exactIdentity, identity: expectedIdentity };
  assertCleanupStat(witnessStat, expected, identityOptions);
  const pathHandle = await openCleanupWitness(
    absolutePath,
    expected,
    identityOptions,
  );
  try {
    const pathStat = await pathHandle.stat({ bigint: true });
    if (objectIdentity(pathStat) !== objectIdentity(witnessStat)) {
      throw new Error(
        `Research cleanup identity changed: ${expected.path}`,
      );
    }
  } finally {
    await pathHandle.close();
  }
}

async function removeWitnessedEntry(
  absolutePath: string,
  expected: StableTreeIdentity,
  witness: FileHandle,
  afterDeleteWitnessOpened?: () => void | Promise<void>,
  afterFinalIdentityCheck?: (
    finalTombstone: string,
  ) => void | Promise<void>,
): Promise<void> {
  const before = await witness.stat({ bigint: true });
  const identity = statIdentity(before);
  const deleteHandle = await openCleanupWitness(
    absolutePath,
    expected,
    {
      exactIdentity: true,
      identity,
    },
  );
  try {
    await afterDeleteWitnessOpened?.();
    await assertWitnessAtPath(absolutePath, deleteHandle, expected);
    const finalTombstone = path.join(
      path.dirname(absolutePath),
      `.${WORKSPACE_PREFIX}final-${randomUUID()}`,
    );
    assertDirectChild(path.dirname(absolutePath), finalTombstone);
    await assertPathAbsent(finalTombstone);
    await fs.rename(absolutePath, finalTombstone);
    await assertPathAbsent(absolutePath);
    await assertWitnessAtPath(finalTombstone, deleteHandle, expected);
    await afterFinalIdentityCheck?.(finalTombstone);
    const beforeRemoval = await witness.stat({ bigint: true });
    // Recheck the sealed entry after the final callback. In particular, a file
    // must still have exactly one link: otherwise an attacker could park the
    // inode, hard-link it back at the tombstone, let us unlink only that alias,
    // and make cleanup report success while the sealed bytes remain.
    assertCleanupStat(beforeRemoval, expected);
    try {
      if (expected.kind === "file") {
        await fs.unlink(finalTombstone);
      } else {
        await fs.rmdir(finalTombstone);
      }
    } catch (error) {
      if (
        expected.kind === "directory" &&
        isNodeError(error, "ENOTEMPTY", "EEXIST")
      ) {
        await assertPathAbsent(absolutePath);
        await assertWitnessAtPath(
          finalTombstone,
          deleteHandle,
          expected,
        );
        await fs.rename(finalTombstone, absolutePath);
        await assertWitnessAtPath(
          absolutePath,
          deleteHandle,
          expected,
        );
        throw new Error(
          `Research cleanup directory contains unexpected entries: ${expected.path}`,
          { cause: error },
        );
      }
      throw error;
    }

    const afterWitness = await witness.stat({ bigint: true });
    const afterDeleteHandle = await deleteHandle.stat({
      bigint: true,
    });
    const linkCountProvesRemoval =
      afterWitness.nlink < beforeRemoval.nlink;
    const darwinNamespaceProvesRemoval =
      expected.kind === "directory" &&
      process.platform === "darwin" &&
      afterWitness.nlink === beforeRemoval.nlink &&
      (await probeDarwinDirectoryLinkState(deleteHandle)) ===
        "unlinked";
    if (
      objectIdentity(afterWitness) !== objectIdentity(beforeRemoval) ||
      objectIdentity(afterDeleteHandle) !== objectIdentity(beforeRemoval) ||
      afterWitness.nlink !== afterDeleteHandle.nlink ||
      (!linkCountProvesRemoval && !darwinNamespaceProvesRemoval)
    ) {
      throw new Error(
        `Research cleanup removed a replacement instead of the sealed entry: ${expected.path}`,
      );
    }
    await assertPathAbsent(absolutePath);
    await assertPathAbsent(finalTombstone);
  } finally {
    await deleteHandle.close();
  }
}

export async function probeDarwinDirectoryLinkState(
  handle: FileHandle,
): Promise<"linked" | "unlinked"> {
  if (process.platform !== "darwin") {
    throw new Error(
      "The Darwin directory link-state verifier is unavailable on this platform.",
    );
  }
  const helper = fileURLToPath(
    new URL(
      "./native/hermsec-darwin-fd-link-state",
      import.meta.url,
    ),
  );
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [], {
      env: {},
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe", handle.fd],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(
        new Error(
          "Darwin cleanup link-state verification timed out.",
        ),
      );
    }, 5_000);
    child.stdout!.on("data", (chunk) => {
      stdout = `${stdout}${String(chunk)}`.slice(-1_024);
    });
    child.stderr!.on("data", (chunk) => {
      stderr = `${stderr}${String(chunk)}`.slice(-1_024);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const state = stdout.trim();
      if (
        code !== 0 ||
        (state !== "linked" && state !== "unlinked")
      ) {
        reject(
          new Error(
            `Darwin cleanup link-state verification failed: ${
              stderr.trim() || `unexpected helper result ${state || "<empty>"}`
            }`,
          ),
        );
        return;
      }
      resolve(state);
    });
  });
}

function assertCleanupStat(
  stat: BigIntStats,
  expected: StableTreeIdentity,
  options: {
    exactIdentity?: boolean;
    identity?: string;
  } = {},
): void {
  const kind =
    stat.isDirectory() && !stat.isSymbolicLink()
      ? "directory"
      : stat.isFile() && !stat.isSymbolicLink()
        ? "file"
        : undefined;
  if (
    kind !== expected.kind ||
    stat.nlink < 1n ||
    (kind === "file" && stat.nlink !== 1n)
  ) {
    throw new Error(
      `Research cleanup requires the sealed ${expected.kind}: ${expected.path}`,
    );
  }
  if (
    objectIdentity(stat) !==
    stableObjectIdentity(expected.identity)
  ) {
    throw new Error(
      `Research cleanup identity changed: ${expected.path}`,
    );
  }
  const exactIdentity =
    options.identity ??
    (options.exactIdentity ? expected.identity : undefined);
  if (
    exactIdentity !== undefined &&
    statIdentity(stat) !== exactIdentity
  ) {
    throw new Error(
      `Research cleanup metadata changed: ${expected.path}`,
    );
  }
}

async function openNoFollow(
  absolutePath: string,
): Promise<FileHandle> {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow === "number" && noFollow !== 0) {
    try {
      return await fs.open(
        absolutePath,
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
  return fs.open(absolutePath, fsConstants.O_RDONLY);
}

async function assertPathAbsent(absolutePath: string): Promise<void> {
  try {
    await fs.lstat(absolutePath);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      return;
    }
    throw error;
  }
  throw new Error(
    `Research cleanup path unexpectedly exists: ${absolutePath}`,
  );
}

function cleanupParentPath(relativePath: string): string {
  const parent = path.posix.dirname(relativePath);
  return parent === "." ? "." : parent;
}

function cleanupAbsolutePath(
  root: string,
  relativePath: string,
): string {
  if (relativePath === ".") {
    return root;
  }
  const absolutePath = path.join(
    root,
    ...relativePath.split("/"),
  );
  assertInside(root, absolutePath);
  return absolutePath;
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

function objectIdentity(stat: BigIntStats): string {
  return `${stat.dev}:${stat.ino}`;
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

function assertFileRecordsEqual(
  actual: StableTreeSnapshot["files"],
  expected: StableTreeSnapshot["files"],
  label: string,
): void {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(
      `Research ${label} does not match its descriptor-verified source.`,
    );
  }
}

function normalizeRelative(value: string): string {
  const normalized = path.posix.normalize(value.replaceAll("\\", "/"));
  if (
    !normalized ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    path.posix.isAbsolute(normalized) ||
    path.win32.isAbsolute(normalized)
  ) {
    throw new Error("Research snapshot paths must be confined and relative.");
  }
  return normalized.replace(/^\.\//u, "");
}

function assertOpaqueId(value: string): void {
  if (!/^[a-f0-9-]{8,80}$/u.test(value)) {
    throw new Error("Research subject snapshot ID must be opaque.");
  }
}

function assertDirectChild(parent: string, candidate: string): void {
  const relative = path.relative(parent, candidate);
  if (
    !relative ||
    relative.includes(path.sep) ||
    relative === ".." ||
    path.isAbsolute(relative)
  ) {
    throw new Error(
      "Research subject snapshot workspace escaped its temporary parent.",
    );
  }
}

function assertInside(
  root: string,
  candidate: string,
  allowRoot = false,
): void {
  const relative = path.relative(root, path.resolve(candidate));
  if (
    (!allowRoot && !relative) ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Research snapshot path escaped its root.");
  }
}

function samePath(left: string, right: string): boolean {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}
