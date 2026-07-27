import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCodeInspectionRuntime } from "../../src/agent/codeInspection.js";
import { dispatchTool } from "../../src/agent/toolDispatcher.js";
import { createInspectionToolRegistry } from "../../src/agent/inspectionTools.js";
import { toolDefinitions } from "../../src/agent/toolRegistry.js";

test("inspection registry exposes only the six bounded read-only tools", async () => {
  await withFixture(async ({ root }) => {
    const runtime = await createCodeInspectionRuntime(root);
    const registry = createInspectionToolRegistry(runtime);

    assert.deepEqual(
      toolDefinitions(registry).map((tool) => tool.function.name),
      [
        "inspect_project",
        "list_files",
        "search_code",
        "read_file_snippet",
        "read_manifest",
        "read_dependency_inventory",
      ],
    );
    assert.equal(registry.tools.has("shell.run" as never), false);
  });
});

test("only trusted untruncated empty-project inventory qualifies as final evidence", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-empty-inspection-tool-"),
  );
  try {
    const runtime = await createCodeInspectionRuntime(root);
    const registry = createInspectionToolRegistry(runtime);
    const context = {
      workspaceRoot: root,
      offlineMode: false,
      userApproved: true,
    };

    const inspected = await dispatchTool(
      registry,
      "inspect_project",
      {},
      context,
    );
    const listed = await dispatchTool(
      registry,
      "list_files",
      { pathIncludes: "filtered-empty" },
      context,
    );

    assert.equal(inspected.qualifiesFinalEvidence, true);
    assert.equal(listed.qualifiesFinalEvidence, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a truncated zero-readable-file profile cannot qualify inventory", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-truncated-secret-profile-"),
  );
  try {
    await fs.writeFile(
      path.join(root, ".env"),
      "SECRET_ONE=fixture-secret-one\n",
      "utf8",
    );
    await fs.writeFile(
      path.join(root, ".env.local"),
      "SECRET_TWO=fixture-secret-two\n",
      "utf8",
    );
    const runtime = await createCodeInspectionRuntime(root, {
      maxFiles: 1,
    });
    const inspected = await dispatchTool(
      createInspectionToolRegistry(runtime),
      "inspect_project",
      {},
      {
        workspaceRoot: root,
        offlineMode: false,
        userApproved: true,
      },
    );

    assert.equal(runtime.profile.indexedFiles, 0);
    assert.equal(runtime.profile.truncated, true);
    assert.equal(inspected.qualifiesFinalEvidence, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("inspection tools validate inputs, redact model output, and deny secret files", async () => {
  await withFixture(async ({ root, secret }) => {
    const runtime = await createCodeInspectionRuntime(root);
    const registry = createInspectionToolRegistry(runtime);
    const context = {
      workspaceRoot: root,
      offlineMode: false,
      userApproved: true,
    };

    const listed = await dispatchTool(registry, "list_files", { limit: 100 }, context);
    const serializedList = JSON.stringify(listed.output);
    assert.doesNotMatch(serializedList, /\.env\.local/u);
    assert.doesNotMatch(serializedList, /\.envrc/u);
    assert.equal(listed.qualifiesFinalEvidence, false);
    assert.equal(runtime.profile.deniedSecretFiles, 2);

    const searched = await dispatchTool(
      registry,
      "search_code",
      { query: "api_key", limit: 10 },
      context,
    );
    const serializedSearch = JSON.stringify(searched.output);
    assert.match(serializedSearch, /\[REDACTED_FOR_MODEL\]/u);
    assert.equal(serializedSearch.includes(secret), false);
    assert.equal(searched.qualifiesFinalEvidence, true);

    await assert.rejects(
      () => dispatchTool(
        registry,
        "read_file_snippet",
        { path: ".env.local", startLine: 1, endLine: 1 },
        context,
      ),
      /secret-bearing files are denied/i,
    );
    await assert.rejects(
      () => dispatchTool(
        registry,
        "read_file_snippet",
        { path: ".envrc", startLine: 1, endLine: 1 },
        context,
      ),
      /secret-bearing files are denied/i,
    );
    await assert.rejects(
      () => dispatchTool(registry, "list_files", { limit: 0 }, context),
      /integer between 1 and 500/i,
    );
    await assert.rejects(
      () => dispatchTool(registry, "list_files", { limit: 10, execute: true }, context),
      /unsupported field/i,
    );
    await assert.rejects(
      () => dispatchTool(registry, "shell.run", {}, context),
      /unregistered/i,
    );
  });
});

test("manifest and dependency inventory tools return bounded repository evidence", async () => {
  await withFixture(async ({ root }) => {
    const runtime = await createCodeInspectionRuntime(root);
    const registry = createInspectionToolRegistry(runtime);
    const context = {
      workspaceRoot: root,
      offlineMode: false,
      userApproved: true,
    };

    const manifest = await dispatchTool(
      registry,
      "read_manifest",
      { path: "package.json", maxChars: 2_000 },
      context,
    );
    assert.match(JSON.stringify(manifest.output), /express/u);
    assert.equal(manifest.qualifiesFinalEvidence, true);

    const inventory = await dispatchTool(
      registry,
      "read_dependency_inventory",
      { limit: 4, maxCharsPerManifest: 2_000 },
      context,
    );
    const serialized = JSON.stringify(inventory.output);
    assert.match(serialized, /package\.json/u);
    assert.match(serialized, /package-lock\.json/u);
    assert.equal(inventory.qualifiesFinalEvidence, true);
  });
});

test("dispatcher rejects a context rooted at a different repository", async () => {
  await withFixture(async ({ root }) => {
    const otherRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-other-root-"));
    try {
      const runtime = await createCodeInspectionRuntime(root);
      const registry = createInspectionToolRegistry(runtime);
      await assert.rejects(
        () => dispatchTool(registry, "inspect_project", {}, {
          workspaceRoot: otherRoot,
          offlineMode: false,
          userApproved: true,
        }),
        /does not match/i,
      );
    } finally {
      await fs.rm(otherRoot, { recursive: true, force: true });
    }
  });
});

test("file reads re-check real paths after the runtime index is created", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-symlink-root-"));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-symlink-outside-"));
  const sourceDir = path.join(root, "src");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(path.join(sourceDir, "app.js"), "const safe = true;\n", "utf8");
    await fs.writeFile(path.join(outside, "app.js"), "const escaped = 'outside';\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);

    await fs.rename(sourceDir, path.join(root, "src-original"));
    try {
      await fs.symlink(outside, sourceDir, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        t.skip("Creating a test junction/symlink is not permitted on this machine.");
        return;
      }
      throw error;
    }

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /escapes the repository root/i,
    );
    const searched = await runtime.searchCode({ query: "outside" });
    assert.equal(searched.matches.length, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  }
});

test("file reads reject an indexed path replaced by a same-root secret symlink", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-secret-symlink-"));
  const sourceDir = path.join(root, "src");
  const sourcePath = path.join(sourceDir, "app.js");
  const secretDirectory = path.join(root, ".env-vault");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(sourcePath, "export const safe = true;\n", "utf8");
    await fs.writeFile(path.join(root, ".env"), "DATABASE_PASSWORD=not-for-models\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);
    await fs.rm(sourcePath);
    try {
      await fs.symlink(path.join(root, ".env"), sourcePath, "file");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        await fs.rm(sourceDir, { recursive: true, force: true });
        await fs.mkdir(secretDirectory);
        await fs.writeFile(
          path.join(secretDirectory, "app.js"),
          "DATABASE_PASSWORD=not-for-models\n",
          "utf8",
        );
        try {
          await fs.symlink(
            secretDirectory,
            sourceDir,
            process.platform === "win32" ? "junction" : "dir",
          );
        } catch (junctionError) {
          if ((junctionError as NodeJS.ErrnoException).code === "EPERM") {
            t.skip("Creating a file symlink or directory junction is not permitted on this machine.");
            return;
          }
          throw junctionError;
        }
      } else {
        throw error;
      }
    }

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /secret-bearing files are denied/i,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("file reads reject an indexed path hard-linked to a denied secret file", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-secret-hardlink-"));
  const sourceDir = path.join(root, "src");
  const sourcePath = path.join(sourceDir, "app.js");
  const secretPath = path.join(root, ".env.local");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(sourcePath, "export const safe = true;\n", "utf8");
    await fs.writeFile(secretPath, "DATABASE_PASSWORD=not-for-models\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);
    await fs.rm(sourcePath);
    await fs.link(secretPath, sourcePath);

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /file identity changed after the inspection index/i,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("file reads retain denied secret identity after its original alias is removed", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-secret-content-"));
  const sourceDir = path.join(root, "src");
  const sourcePath = path.join(sourceDir, "app.js");
  const secretPath = path.join(root, ".env");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(sourcePath, "export const safe = true;\n", "utf8");
    await fs.writeFile(secretPath, "opaque-secret-material\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);
    await fs.rm(sourcePath);
    await fs.link(secretPath, sourcePath);
    await fs.rm(secretPath);

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /file identity changed after the inspection index/i,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("file reads reject a late-created secret hard link after the secret path is deleted", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-late-secret-hardlink-"));
  const sourceDir = path.join(root, "src");
  const sourcePath = path.join(sourceDir, "app.js");
  const lateSecretPath = path.join(root, ".env.late");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(sourcePath, "export const safe = true;\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);

    const unchanged = await runtime.readFileSnippet({
      path: "src/app.js",
      startLine: 1,
      endLine: 1,
    });
    assert.match(unchanged.text, /safe = true/u);

    await fs.rm(sourcePath);
    await fs.writeFile(lateSecretPath, "opaque-late-secret-material\n", "utf8");
    await fs.link(lateSecretPath, sourcePath);
    await fs.rm(lateSecretPath);

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /file identity changed after the inspection index/i,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("file reads reject high-confidence environment secret content written after indexing", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-secret-content-"));
  const sourceDir = path.join(root, "src");
  const sourcePath = path.join(sourceDir, "app.js");
  try {
    await fs.mkdir(sourceDir);
    await fs.writeFile(sourcePath, "export const safe = true;\n", "utf8");
    const runtime = await createCodeInspectionRuntime(root);
    await fs.writeFile(
      sourcePath,
      "DATABASE_URL=postgres://:password@db.test/app\n",
      "utf8",
    );

    await assert.rejects(
      () => runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 }),
      /environment-like secret content is denied/i,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("inspection schemas reject inherited inputs and do not read prototype values", async () => {
  await withFixture(async ({ root }) => {
    const runtime = await createCodeInspectionRuntime(root);
    const registry = createInspectionToolRegistry(runtime);
    const context = {
      workspaceRoot: root,
      offlineMode: false,
      userApproved: true,
    };
    const inherited = Object.create({ limit: 1 }) as Record<string, unknown>;

    await assert.rejects(
      () => dispatchTool(registry, "list_files", inherited, context),
      /plain JSON object/i,
    );
  });
});

async function withFixture(
  run: (fixture: { root: string; secret: string }) => Promise<void>,
): Promise<void> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-inspection-"));
  const secret = ["sk", "test-tool-secret-1234567890abcdef"].join("-");
  try {
    await fs.mkdir(path.join(root, "src"));
    await fs.writeFile(
      path.join(root, "src", "app.js"),
      [
        `const api_key = "${secret}";`,
        "export function run(input) { return eval(input); }",
      ].join("\n"),
      "utf8",
    );
    await fs.writeFile(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "inspection-fixture",
        dependencies: { express: "4.18.0" },
      }, null, 2),
      "utf8",
    );
    await fs.writeFile(
      path.join(root, "package-lock.json"),
      JSON.stringify({ name: "inspection-fixture", lockfileVersion: 3 }),
      "utf8",
    );
    await fs.writeFile(path.join(root, ".env.local"), `API_KEY=${secret}\n`, "utf8");
    await fs.writeFile(path.join(root, ".envrc"), `export DATABASE_PASSWORD=${secret}\n`, "utf8");
    await run({ root, secret });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
