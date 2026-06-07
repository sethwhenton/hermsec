import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import {
  addWorkspaceFromPath,
  chatTurn,
  getDesktopState,
  scanWorkspace,
  updateSecurityIntel,
} from "../../src/desktop/api.js";

test("desktop API scans a real vulnerable fixture and saves report artifacts", async (t) => {
  await withTempHermsecHome(t);
  const fixture = path.resolve("tests/fixtures/repos/node-express-vulnerable");
  const workspace = await addWorkspaceFromPath(fixture);
  const scan = await scanWorkspace({ workspaceId: workspace.id, mode: "offline" });

  assert.equal(scan.workspace.id, workspace.id);
  assert.equal(scan.run.summary.total > 0, true);
  assert.equal(scan.run.findings.some((finding) => finding.category === "secret"), true);
  assert.ok(scan.report.htmlPath);
  await assertFileExists(scan.report.htmlPath);
  await assertFileExists(scan.report.documentPath);

  const state = await getDesktopState(process.cwd());
  assert.equal(state.activeWorkspace?.id, workspace.id);
  assert.equal(state.reports.some((report) => report.scanId === scan.run.id), true);
});

test("desktop API routes chat slash commands through Hermsec tools", async (t) => {
  await withTempHermsecHome(t);
  const fixture = path.resolve("tests/fixtures/repos/node-express-vulnerable");
  const workspace = await addWorkspaceFromPath(fixture);
  const result = await chatTurn(process.cwd(), {
    workspaceId: workspace.id,
    content: "/scan",
  });

  assert.match(result.message, /findings/i);
  assert.ok(result.scan);
  assert.equal(result.scan.run.summary.total > 0, true);
  assert.equal(result.session?.messages.some((message) => message.role === "assistant"), true);
});

test("desktop API exposes cached intel for the desktop news panel", async (t) => {
  await withTempHermsecHome(t);
  const intel = await updateSecurityIntel(process.cwd(), true);
  assert.equal(intel.feed.length > 0, true);
  assert.match(intel.summaryText ?? intel.message, /security|vulnerab|advis/i);
});

async function assertFileExists(filePath: string): Promise<void> {
  const stat = await fs.stat(filePath);
  assert.equal(stat.isFile(), true);
}

async function withTempHermsecHome(t: TestContext): Promise<string> {
  const previous = process.env.HERMSEC_HOME;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-desktop-api-"));
  process.env.HERMSEC_HOME = directory;
  t.after(async () => {
    if (previous === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previous;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  return directory;
}
