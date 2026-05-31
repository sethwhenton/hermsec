import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCliToolbox } from "../../src/tui/cli.js";

test("TUI scan adapter uses the real scan harness", async () => {
  const previousHome = process.env.HERMSEC_HOME;
  const hermsecHome = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-tui-scan-"));
  process.env.HERMSEC_HOME = hermsecHome;

  try {
    const fixture = path.resolve("tests/fixtures/repos/node-express-vulnerable");
    const scan = createCliToolbox(process.cwd()).scan;
    assert.ok(scan);

    const result = await scan({
      target: fixture,
      mode: "offline",
      preference: "full",
    });

    if (!result.ok || !result.data) {
      assert.fail(result.message);
    }
    assert.equal(result.data.status, "completed");
    assert.equal(result.data.summary?.critical ?? 0, 1);
    assert.match(result.message, /Scan completed:/);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previousHome;
    }
    await fs.rm(hermsecHome, { recursive: true, force: true });
  }
});
