import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadUserConfig, setConfigValue } from "../../src/storage/userConfig.js";

test("config stores provider credential env references without storing key values", async () => {
  await withHermsecHome(async (workspace) => {
    await setConfigValue({
      cwd: workspace,
      key: "providerCredentialEnv",
      value: "OPENROUTER_API_KEY",
    });

    const config = await loadUserConfig();
    assert.deepEqual(config.providerCredentialRef, {
      kind: "env",
      name: "OPENROUTER_API_KEY",
    });

    const raw = await fs.readFile(path.join(workspace, "config.json"), "utf8");
    assert.equal(raw.includes("OPENROUTER_API_KEY"), true);
    assert.equal(raw.includes("sk-"), false);
  });
});

test("config rejects raw-looking provider key values", async () => {
  await withHermsecHome(async (workspace) => {
    await assert.rejects(
      () => setConfigValue({
        cwd: workspace,
        key: "providerCredentialEnv",
        value: "sk-test-raw-key-should-not-be-stored-1234567890",
      }),
      /environment variable name/,
    );
  });
});

async function withHermsecHome(run: (workspace: string) => Promise<void>): Promise<void> {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-config-test-"));
  const previousHome = process.env.HERMSEC_HOME;
  process.env.HERMSEC_HOME = workspace;
  try {
    await run(workspace);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previousHome;
    }
    await fs.rm(workspace, { recursive: true, force: true });
  }
}
