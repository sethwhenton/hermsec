import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("compiled CLI help returns a bounded smoke response", () => {
  const compiledRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const cliPath = path.join(compiledRoot, "src", "bin", "hermsec.js");
  const hermsecHome = fs.mkdtempSync(path.join(os.tmpdir(), "hermsec-cli-smoke-"));

  try {
    const result = spawnSync(process.execPath, [cliPath, "--help"], {
      cwd: process.cwd(),
      env: { ...process.env, HERMSEC_HOME: hermsecHome },
      encoding: "utf8",
      timeout: 2_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;

    assert.equal(result.status, 0, output);
    assert.match(output, /hermsec/i);
    assert.doesNotMatch(output, /HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE/);
  } finally {
    fs.rmSync(hermsecHome, { recursive: true, force: true });
  }
});

test("compiled CLI defaults to the TUI entrypoint without hanging in non-interactive mode", () => {
  const compiledRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const cliPath = path.join(compiledRoot, "src", "bin", "hermsec.js");
  const hermsecHome = fs.mkdtempSync(path.join(os.tmpdir(), "hermsec-cli-tui-"));

  try {
    const result = spawnSync(process.execPath, [cliPath], {
      cwd: process.cwd(),
      env: { ...process.env, HERMSEC_HOME: hermsecHome },
      encoding: "utf8",
      timeout: 2_000,
    });
    const output = `${result.stdout}\n${result.stderr}`;

    assert.equal(result.status, 0, output);
    assert.match(output, /Hermsec TUI detected a non-interactive terminal/);
    assert.doesNotMatch(output, /HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE/);
  } finally {
    fs.rmSync(hermsecHome, { recursive: true, force: true });
  }
});
