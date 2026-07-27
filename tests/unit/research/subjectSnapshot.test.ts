import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { validateFixtureLayout } from "../../../src/eval/fixtureLayout.js";
import type { FixtureManifestV2 } from "../../../src/eval/schema.js";
import {
  captureStableTree,
  type StableTreeLimits,
} from "../../../src/research/stableFiles.js";
import {
  createSubjectSnapshotWorkspace,
  materializeFixtureSnapshots,
  probeDarwinDirectoryLinkState,
  removeSubjectSnapshotWorkspace,
  sealSubjectSnapshotWorkspace,
} from "../../../src/research/subjectSnapshot.js";

const LIMITS = {
  maxDepth: 16,
  maxDirectories: 100,
  maxFiles: 100,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 10 * 1024 * 1024,
} satisfies StableTreeLimits;

const OPAQUE_ID = "12345678abcdef00";

test("snapshot cleanup removes a sealed inventory without rediscovering paths", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  t.after(async () => {
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await removeSubjectSnapshotWorkspace(workspace);
  await assert.rejects(
    fs.lstat(workspace.root),
    (error: unknown) => isNodeError(error, "ENOENT"),
  );
});

test("snapshot cleanup rejects a post-inspection hardlink replacement and preserves both targets", async (t) => {
  const externalRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-cleanup-external-"),
  );
  const externalFile = path.join(externalRoot, "external.txt");
  await fs.writeFile(externalFile, "external content\n", "utf8");
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedFile: string | undefined;
  t.after(async () => {
    if (parkedFile) {
      await fs.rm(parkedFile, { force: true });
    }
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.rm(externalRoot, { recursive: true, force: true });
  });

  const swapTarget = `${OPAQUE_ID}/subject/nested/app.js`;
  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterTombstoneInspection: async (
        relativePath,
        tombstone,
        root,
      ) => {
        if (relativePath !== swapTarget) {
          return;
        }
        cleanupRoot = root;
        parkedFile = `${tombstone}.sealed`;
        await fs.rename(tombstone, parkedFile);
        await fs.link(externalFile, tombstone);
      },
    }),
    /Research cleanup (?:identity changed|requires the sealed file)/u,
  );
  assert.equal(
    await fs.readFile(externalFile, "utf8"),
    "external content\n",
  );
  assert.ok(parkedFile);
  assert.equal(
    await fs.readFile(parkedFile, "utf8"),
    "export const safe = true;\n",
  );
});

test("snapshot cleanup rejects a post-inspection directory link replacement without traversing it", async (t) => {
  const externalRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-cleanup-external-"),
  );
  const sentinel = path.join(externalRoot, "sentinel.txt");
  await fs.writeFile(sentinel, "do not delete\n", "utf8");
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedDirectory: string | undefined;
  let injectedLink: string | undefined;
  let supported = true;
  t.after(async () => {
    if (injectedLink) {
      await removeLinkOnly(injectedLink);
    }
    if (parkedDirectory) {
      await fs.rm(parkedDirectory, {
        recursive: true,
        force: true,
      });
    }
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.rm(externalRoot, { recursive: true, force: true });
  });

  const swapTarget = `${OPAQUE_ID}/subject/nested`;
  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterTombstoneInspection: async (
        relativePath,
        tombstone,
        root,
      ) => {
        if (relativePath !== swapTarget) {
          return;
        }
        cleanupRoot = root;
        parkedDirectory = `${tombstone}.sealed`;
        injectedLink = tombstone;
        await fs.rename(tombstone, parkedDirectory);
        try {
          await fs.symlink(
            externalRoot,
            tombstone,
            process.platform === "win32" ? "junction" : "dir",
          );
        } catch (error) {
          supported = false;
          injectedLink = undefined;
          await fs.rename(parkedDirectory, tombstone);
          parkedDirectory = undefined;
          throw error;
        }
      },
    }),
  );
  if (!supported) {
    t.skip("Directory link creation is unavailable on this platform.");
    return;
  }
  assert.equal(await fs.readFile(sentinel, "utf8"), "do not delete\n");
  assert.ok(parkedDirectory);
  assert.equal((await fs.lstat(parkedDirectory)).isDirectory(), true);
});

test("snapshot cleanup rejects replacement of the quarantined root before traversal", async (t) => {
  const externalRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-cleanup-external-"),
  );
  const sentinel = path.join(externalRoot, "sentinel.txt");
  await fs.writeFile(sentinel, "do not delete\n", "utf8");
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedRoot: string | undefined;
  let injectedLink: string | undefined;
  let supported = true;
  t.after(async () => {
    if (injectedLink) {
      await removeLinkOnly(injectedLink);
    }
    if (parkedRoot) {
      await fs.rm(parkedRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.rm(externalRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterRootInspection: async (root, phase) => {
        if (phase !== "quarantined") {
          return;
        }
        cleanupRoot = root;
        parkedRoot = `${root}.sealed`;
        injectedLink = root;
        await fs.rename(root, parkedRoot);
        try {
          await fs.symlink(
            externalRoot,
            root,
            process.platform === "win32" ? "junction" : "dir",
          );
        } catch (error) {
          supported = false;
          injectedLink = undefined;
          await fs.rename(parkedRoot, root);
          parkedRoot = undefined;
          throw error;
        }
      },
    }),
  );
  if (!supported) {
    t.skip("Cleanup-root link creation is unavailable on this platform.");
    return;
  }
  assert.equal(await fs.readFile(sentinel, "utf8"), "do not delete\n");
  assert.ok(cleanupRoot);
  assert.ok(parkedRoot);
  assert.equal(
    await fs.readFile(
      path.join(
        parkedRoot,
        OPAQUE_ID,
        "subject",
        "nested",
        "app.js",
      ),
      "utf8",
    ),
    "export const safe = true;\n",
  );
});

test("snapshot cleanup rejects a root replacement after the final delete witness opens", async (t) => {
  const externalRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-cleanup-external-"),
  );
  const sentinel = path.join(externalRoot, "sentinel.txt");
  await fs.writeFile(sentinel, "do not delete\n", "utf8");
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let parkedRoot: string | undefined;
  let injectedLink: string | undefined;
  let supported = true;
  t.after(async () => {
    if (injectedLink) {
      await removeLinkOnly(injectedLink);
    }
    if (parkedRoot) {
      await fs.rm(parkedRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.rm(externalRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterRootInspection: async (root, phase) => {
        if (phase !== "before-remove") {
          return;
        }
        parkedRoot = `${root}.sealed`;
        injectedLink = root;
        await fs.rename(root, parkedRoot);
        try {
          await fs.symlink(
            externalRoot,
            root,
            process.platform === "win32" ? "junction" : "dir",
          );
        } catch (error) {
          supported = false;
          injectedLink = undefined;
          await fs.rename(parkedRoot, root);
          parkedRoot = undefined;
          throw error;
        }
      },
    }),
  );
  if (!supported) {
    t.skip("Final cleanup-root link creation is unavailable.");
    return;
  }
  assert.equal(await fs.readFile(sentinel, "utf8"), "do not delete\n");
  assert.ok(parkedRoot);
  assert.equal((await fs.lstat(parkedRoot)).isDirectory(), true);
});

test("snapshot cleanup detects a successfully removed empty-directory replacement", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let parkedRoot: string | undefined;
  t.after(async () => {
    if (parkedRoot) {
      await fs.rm(parkedRoot, { recursive: true, force: true });
    }
    await fs.rm(workspace.root, { recursive: true, force: true });
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterRootInspection: async (root, phase) => {
        if (phase !== "before-remove") {
          return;
        }
        parkedRoot = `${root}.sealed`;
        await fs.rename(root, parkedRoot);
        await fs.mkdir(root, { mode: 0o700 });
      },
    }),
    /Research cleanup identity changed/u,
  );
  assert.ok(parkedRoot);
  assert.equal((await fs.lstat(parkedRoot)).isDirectory(), true);
});

test("snapshot cleanup detects a directory swap after the final identity check", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedDirectory: string | undefined;
  t.after(async () => {
    if (parkedDirectory) {
      await fs.rm(parkedDirectory, {
        recursive: true,
        force: true,
      });
    }
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterFinalTombstoneInspection: async (
        relativePath,
        finalTombstone,
        root,
      ) => {
        if (!relativePath.endsWith("/subject/nested")) {
          return;
        }
        cleanupRoot = root;
        parkedDirectory = `${finalTombstone}.sealed`;
        await fs.rename(finalTombstone, parkedDirectory);
        await fs.mkdir(finalTombstone, { mode: 0o700 });
      },
    }),
    /Research cleanup removed a replacement/u,
  );
  assert.ok(parkedDirectory);
  assert.equal(
    (await fs.lstat(parkedDirectory)).isDirectory(),
    true,
  );
});

test("snapshot cleanup rejects a hardlink retained after the final identity check", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedFile: string | undefined;
  t.after(async () => {
    if (parkedFile) {
      await fs.rm(parkedFile, { force: true });
    }
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterFinalTombstoneInspection: async (
        relativePath,
        finalTombstone,
        root,
      ) => {
        if (!relativePath.endsWith("/subject/nested/app.js")) {
          return;
        }
        cleanupRoot = root;
        parkedFile = `${finalTombstone}.sealed`;
        await fs.rename(finalTombstone, parkedFile);
        await fs.link(parkedFile, finalTombstone);
      },
    }),
    /Research cleanup requires the sealed file/u,
  );
  assert.ok(parkedFile);
  assert.equal(
    await fs.readFile(parkedFile, "utf8"),
    "export const safe = true;\n",
  );
});

test("snapshot cleanup detects a root swap after the final identity check", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let parkedRoot: string | undefined;
  t.after(async () => {
    if (parkedRoot) {
      await fs.rm(parkedRoot, { recursive: true, force: true });
    }
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterFinalTombstoneInspection: async (
        relativePath,
        finalTombstone,
        root,
      ) => {
        if (relativePath !== ".") {
          return;
        }
        cleanupRoot = root;
        parkedRoot = `${finalTombstone}.sealed`;
        await fs.rename(finalTombstone, parkedRoot);
        await fs.mkdir(finalTombstone, { mode: 0o700 });
      },
    }),
    /Research cleanup removed a replacement/u,
  );
  assert.ok(parkedRoot);
  assert.equal((await fs.lstat(parkedRoot)).isDirectory(), true);
});

test("Darwin cleanup verifier distinguishes linked, renamed, and removed directories", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Darwin open-directory namespace semantics are macOS-specific.");
    return;
  }
  const parent = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-darwin-link-state-"),
  );
  const directory = path.join(parent, "directory");
  const renamed = path.join(parent, "renamed");
  await fs.mkdir(directory, { mode: 0o700 });
  const handle = await fs.open(directory, "r");
  t.after(async () => {
    await handle.close();
    await fs.rm(parent, { recursive: true, force: true });
  });

  assert.equal(
    await probeDarwinDirectoryLinkState(handle),
    "linked",
  );
  await fs.rename(directory, renamed);
  assert.equal(
    await probeDarwinDirectoryLinkState(handle),
    "linked",
  );
  await fs.rmdir(renamed);
  assert.equal(
    await probeDarwinDirectoryLinkState(handle),
    "unlinked",
  );
});

test("snapshot cleanup quarantines unexpected entries instead of recursively discovering them", async (t) => {
  const { sourceRoot, workspace } = await createSealedWorkspace();
  let cleanupRoot: string | undefined;
  let unexpectedFile: string | undefined;
  t.after(async () => {
    if (cleanupRoot) {
      await fs.rm(cleanupRoot, { recursive: true, force: true });
    }
    await fs.rm(sourceRoot, { recursive: true, force: true });
  });

  await assert.rejects(
    removeSubjectSnapshotWorkspace(workspace, {
      afterRootInspection: async (root, phase) => {
        if (phase !== "quarantined") {
          return;
        }
        cleanupRoot = root;
        unexpectedFile = path.join(root, "unexpected.txt");
        await fs.writeFile(unexpectedFile, "preserve me\n", "utf8");
      },
    }),
    /contains unexpected entries/u,
  );
  assert.ok(unexpectedFile);
  assert.equal(
    await fs.readFile(unexpectedFile, "utf8"),
    "preserve me\n",
  );
});

async function createSealedWorkspace(): Promise<{
  sourceRoot: string;
  workspace: Awaited<
    ReturnType<typeof createSubjectSnapshotWorkspace>
  >;
}> {
  const sourceRoot = await createSourceFixture();
  const workspace = await createSubjectSnapshotWorkspace();
  const sourceSnapshot = await captureStableTree(sourceRoot, LIMITS);
  const manifest = fixtureManifest();
  const layout = validateFixtureLayout(
    manifest,
    sourceSnapshot.identities,
  );
  await materializeFixtureSnapshots({
    workspace,
    sourceRoot,
    sourceSnapshot,
    layout,
    opaqueId: OPAQUE_ID,
    limits: LIMITS,
  });
  await sealSubjectSnapshotWorkspace(workspace, LIMITS);
  return { sourceRoot, workspace };
}

async function removeLinkOnly(linkPath: string): Promise<void> {
  try {
    const stat = await fs.lstat(linkPath);
    if (!stat.isSymbolicLink()) {
      throw new Error(`Expected a link at ${linkPath}.`);
    }
    await fs.unlink(linkPath);
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) {
      throw error;
    }
  }
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

async function createSourceFixture(): Promise<string> {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-cleanup-source-"),
  );
  await fs.mkdir(path.join(root, "project", "nested"), {
    recursive: true,
  });
  await fs.writeFile(
    path.join(root, "project", "nested", "app.js"),
    "export const safe = true;\n",
    "utf8",
  );
  await fs.writeFile(
    path.join(root, "fixture.json"),
    `${JSON.stringify(fixtureManifest(), null, 2)}\n`,
    "utf8",
  );
  await fs.writeFile(
    path.join(root, "truth.json"),
    '{"schemaVersion":"2.0","fixtureId":"cleanup-fixture","findings":[]}\n',
    "utf8",
  );
  return root;
}

function fixtureManifest(): FixtureManifestV2 {
  return {
    schemaVersion: "2.0",
    id: "cleanup-fixture",
    pairId: "cleanup-pair",
    variant: "clean",
    language: "javascript",
    projectRoot: "project",
    evaluatorFiles: ["truth.json"],
    entrypoints: ["nested/app.js"],
    sourceFiles: ["nested/app.js"],
    supportedVulnerabilityClasses: ["sql-injection"],
    expectedFindingCount: 0,
    pairedFixtureId: "cleanup-vulnerable",
    safety: {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
  };
}
