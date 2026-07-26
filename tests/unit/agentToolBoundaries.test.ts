import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCodeInspectionRuntime } from "../../src/agent/codeInspection.js";

const workspaceRoot = path.resolve(
  "tests/fixtures/repos/node-express-clean/project",
);

test("repo inspection snippets reject traversal outside the target repository", async () => {
  const runtime = await createCodeInspectionRuntime(workspaceRoot);

  await assert.rejects(
    () => runtime.readFileSnippet({
      path: "../outside-target.txt",
      startLine: 1,
      endLine: 5,
    }),
    /outside|escapes|relative to the repository/i,
  );
});

test("repo inspection snippets reject absolute paths outside the target repository", async () => {
  const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-outside-repo-"));
  const outsideFile = path.join(outsideDir, "outside.txt");

  try {
    await fs.writeFile(outsideFile, "outside target repo\n", "utf8");
    const runtime = await createCodeInspectionRuntime(workspaceRoot);

    await assert.rejects(
      () => runtime.readFileSnippet({
        path: outsideFile,
        startLine: 1,
        endLine: 1,
      }),
      /outside|escapes|relative to the repository/i,
    );
  } finally {
    await fs.rm(outsideDir, { recursive: true, force: true });
  }
});

test("repo inspection search rejects path prefixes outside the target repository", async () => {
  const runtime = await createCodeInspectionRuntime(workspaceRoot);

  await assert.rejects(
    () => runtime.searchCode({
      query: "app",
      pathPrefix: "../outside-target",
    }),
    /outside|escapes|relative to the repository/i,
  );
});
