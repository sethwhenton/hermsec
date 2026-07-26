import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import {
  inspectTarGzipArchive,
  inspectZipArchive,
  validateArchiveEntries,
  verifyExtractedTree,
} from "../scripts/runtime-archive-safety.mjs";
import {
  assertRuntimeProvenance,
  createRuntimeManifest,
} from "../scripts/runtime-python-layout.mjs";
import {
  buildPortablePythonLauncher,
  findPortableLauncherCompiler,
} from "../scripts/portable-python-launcher-build.mjs";

test("archive inventory rejects absolute, traversal, hardlink, and special entries", () => {
  assert.doesNotThrow(() => validateArchiveEntries([
    { path: "python/bin/python3", type: "file", size: 1 },
  ]));
  assert.throws(() => validateArchiveEntries([{ path: "../escape", type: "file", size: 1 }]));
  assert.throws(() => validateArchiveEntries([{ path: "C:\\escape", type: "file", size: 1 }]));
  assert.throws(() => validateArchiveEntries([{ path: "/escape", type: "file", size: 1 }]));
  assert.throws(() => validateArchiveEntries([
    { path: "python/link", type: "hardlink", linkTarget: "python/bin/python3", size: 0 },
  ]));
  assert.throws(() => validateArchiveEntries([{ path: "python/device", type: "special", size: 0 }]));
});

test("archive inventory accepts only confined symlinks when explicitly enabled", () => {
  const safe = [{ path: "python/bin/python3", type: "symlink", linkTarget: "python3.12", size: 0 }];
  assert.throws(() => validateArchiveEntries(safe));
  assert.doesNotThrow(() => validateArchiveEntries(safe, { allowSafeSymlinks: true }));
  assert.throws(() => validateArchiveEntries([
    { path: "python/bin/python3", type: "symlink", linkTarget: "../../../escape", size: 0 },
  ], { allowSafeSymlinks: true }));
  assert.throws(() => validateArchiveEntries([
    { path: "python/bin/python3", type: "symlink", linkTarget: "/outside", size: 0 },
  ], { allowSafeSymlinks: true }));
});

test("archive inventory rejects duplicate and case-colliding paths", () => {
  assert.throws(() => validateArchiveEntries([
    { path: "bin/tool", type: "file", size: 1 },
    { path: "bin/./tool", type: "file", size: 1 },
  ]));
  assert.throws(() => validateArchiveEntries([
    { path: "bin/Tool", type: "file", size: 1 },
    { path: "bin/tool", type: "file", size: 1 },
  ], { caseInsensitivePaths: true }));
  assert.doesNotThrow(() => validateArchiveEntries([
    { path: "bin/Tool", type: "file", size: 1 },
    { path: "bin/tool", type: "file", size: 1 },
  ], { caseInsensitivePaths: false }));
});

test("ZIP preflight binds every central-directory name to its local header before extraction", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-zip-header-"));
  try {
    const archivePath = path.join(root, "mismatched.zip");
    await fs.writeFile(archivePath, storedZip({ localName: "../escape", centralName: "runtime/tool" }));
    assert.throws(() => inspectZipArchive(archivePath), /central and local headers disagree/u);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("ZIP preflight accepts bounded data-descriptor entries only when their local name still matches", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-zip-descriptor-"));
  try {
    const archivePath = path.join(root, "descriptor.zip");
    await fs.writeFile(archivePath, storedZip({ localName: "runtime/tool", centralName: "runtime/tool", dataDescriptor: true }));
    assert.doesNotThrow(() => inspectZipArchive(archivePath));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("TAR gzip preflight enforces compressed and decompressed byte ceilings", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-tar-limit-"));
  try {
    const archivePath = path.join(root, "oversized.tar.gz");
    await fs.writeFile(archivePath, gzipSync(Buffer.alloc(4096, 0x61)));
    assert.throws(
      () => inspectTarGzipArchive(archivePath, { maxCompressedBytes: 1 }),
      /compressed size limit/u,
    );
    assert.throws(
      () => inspectTarGzipArchive(archivePath, { maxUncompressedBytes: 64 }),
      /uncompressed size limit/u,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("post-extract verification rejects hardlinks", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-hardlink-"));
  try {
    const source = path.join(root, "source");
    const alias = path.join(root, "alias");
    await fs.writeFile(source, "scanner");
    await fs.link(source, alias);
    assert.throws(() => verifyExtractedTree(root));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("runtime provenance rejects a modified staged lock", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-provenance-"));
  try {
    await writeRuntimeFixture(root);
    assert.doesNotThrow(() => assertRuntimeProvenance(root));
    await fs.appendFile(path.join(root, "provenance/python-locks/win32-x64.txt"), "tampered");
    assert.throws(() => assertRuntimeProvenance(root), /hash mismatch|file manifest/u);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("runtime file inventory rejects modified scanner and embedded Python bytes", async () => {
  for (const relativePath of ["bin/semgrep.exe", "python-runtime/python.exe"]) {
    const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-tree-"));
    try {
      await writeRuntimeFixture(root);
      assert.doesNotThrow(() => assertRuntimeProvenance(root));
      await fs.appendFile(path.join(root, relativePath), "tampered");
      assert.throws(
        () => assertRuntimeProvenance(root),
        /file manifest|tree hash/u,
        relativePath,
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
});

test("runtime manifests are deterministic and contain no wall-clock timestamp", async () => {
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-deterministic-"));
  try {
    const input = await writeRuntimeFixtureFiles(root);
    const first = createRuntimeManifest(input);
    const second = createRuntimeManifest(input);
    assert.deepEqual(second, first);
    assert.equal(Object.hasOwn(first, "generatedAt"), false);
    assert.match(first.treeSha256, /^[a-f0-9]{64}$/u);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("Windows portable launcher staging is byte-reproducible", async (t) => {
  if (process.platform !== "win32") {
    t.skip("The native launcher is a Windows PE executable.");
    return;
  }
  const compiler = findPortableLauncherCompiler();
  if (!compiler) {
    t.skip("MSVC is supplied by the Windows release workflow, not ordinary local test shells.");
    return;
  }
  const root = await fs.mkdtemp(path.join(process.cwd(), ".tmp-runtime-launcher-repro-"));
  try {
    const sourcePath = path.resolve(import.meta.dirname, "../scripts/portable-python-launcher.c");
    const firstOutput = path.join(root, "first", "launcher.exe");
    const secondOutput = path.join(root, "second", "launcher.exe");
    await fs.mkdir(path.dirname(firstOutput), { recursive: true });
    await fs.mkdir(path.dirname(secondOutput), { recursive: true });
    buildPortablePythonLauncher({ sourcePath, outputPath: firstOutput, compiler });
    buildPortablePythonLauncher({ sourcePath, outputPath: secondOutput, compiler });
    const [first, second] = await Promise.all([fs.readFile(firstOutput), fs.readFile(secondOutput)]);
    assert.equal(
      createHash("sha256").update(first).digest("hex"),
      createHash("sha256").update(second).digest("hex"),
      "two independent staging invocations must produce the same launcher bytes",
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function writeRuntimeFixture(root: string): Promise<void> {
  const input = await writeRuntimeFixtureFiles(root);
  const manifest = createRuntimeManifest(input);
  await fs.writeFile(
    path.join(root, "manifest.json"),
    JSON.stringify(manifest, null, 2),
    "utf8",
  );
}

async function writeRuntimeFixtureFiles(root: string): Promise<{
  toolsRoot: string;
  platform: NodeJS.Platform;
  arch: string;
  provenance: Array<{ id: string; path: string; sha256: string }>;
  portablePython: Record<string, unknown>;
  tools: Array<{ id: string; version: string; kind: string }>;
}> {
  const provenance = [
    ["runtime-assets", "provenance/runtime-asset-checksums.json"],
    ["python-lock-provenance", "provenance/python-lock-provenance.json"],
    ["python-direct-requirements", "provenance/python-scanners.in"],
    ["python-platform-lock", "provenance/python-locks/win32-x64.txt"],
  ] as const;
  const entries = [];
  for (const [id, relative] of provenance) {
    const file = path.join(root, relative);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, id);
    entries.push({
      id,
      path: relative,
      sha256: createHash("sha256").update(id).digest("hex"),
    });
  }
  await fs.mkdir(path.join(root, "bin"), { recursive: true });
  await fs.mkdir(path.join(root, "python-runtime"), { recursive: true });
  await fs.writeFile(path.join(root, "bin/semgrep.exe"), "scanner");
  await fs.writeFile(path.join(root, "python-runtime/python.exe"), "python");
  return {
    toolsRoot: root,
    platform: process.platform,
    arch: process.arch,
    provenance: entries,
    portablePython: { version: "3.12.11" },
    tools: [{ id: "semgrep", version: "test", kind: "python-module" }],
  };
}

function storedZip(input: { localName: string; centralName: string; dataDescriptor?: boolean }): Buffer {
  const data = Buffer.from("x");
  const localName = Buffer.from(input.localName, "utf8");
  const centralName = Buffer.from(input.centralName, "utf8");
  const descriptor = input.dataDescriptor ? Buffer.alloc(16) : Buffer.alloc(0);
  const local = Buffer.alloc(30 + localName.length + data.length + descriptor.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(input.dataDescriptor ? 0x0008 : 0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(0, 14);
  local.writeUInt32LE(input.dataDescriptor ? 0 : data.length, 18);
  local.writeUInt32LE(input.dataDescriptor ? 0 : data.length, 22);
  local.writeUInt16LE(localName.length, 26);
  local.writeUInt16LE(0, 28);
  localName.copy(local, 30);
  data.copy(local, 30 + localName.length);
  if (input.dataDescriptor) {
    const descriptorOffset = 30 + localName.length + data.length;
    local.writeUInt32LE(0x08074b50, descriptorOffset);
    local.writeUInt32LE(0, descriptorOffset + 4);
    local.writeUInt32LE(data.length, descriptorOffset + 8);
    local.writeUInt32LE(data.length, descriptorOffset + 12);
  }

  const central = Buffer.alloc(46 + centralName.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(input.dataDescriptor ? 0x0008 : 0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(0, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(centralName.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  centralName.copy(central, 46);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(local.length, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([local, central, eocd]);
}
