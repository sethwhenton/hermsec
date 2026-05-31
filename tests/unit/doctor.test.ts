import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDoctorCommand } from "../../src/cli/commands/doctor.js";

type DoctorData = {
  checks: Array<{ id: string; status: string }>;
  summary: { fail: number };
};

const hardenedNpmrc = [
  "ignore-scripts=true",
  "engine-strict=true",
  "save-exact=true",
  "package-lock=true",
  "save-prefix=",
  "",
].join("\n");

test("doctor skips explicitly optional tools while passing required checks", async () => {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-doctor-pass-"));
  const bin = path.join(workspace, "bin");
  await fs.mkdir(bin);
  await fs.writeFile(path.join(workspace, ".npmrc"), hardenedNpmrc, "utf8");
  await writeStubExecutable(bin, "git");
  await writeStubExecutable(bin, "npm");

  try {
    const outcome = await runDoctorCommand(["--json"], {
      cwd: workspace,
      env: doctorEnv(bin),
      now: () => new Date("2026-05-31T00:00:00.000Z"),
    });

    if (!outcome.result.ok) {
      assert.fail(outcome.result.message);
    }
    assert.equal(outcome.exitCode, 0);

    const data = outcome.result.data as DoctorData | undefined;
    const checks = data?.checks ?? [];
    assert.equal(data?.summary.fail, 0);
    assert.equal(checks.find((check) => check.id === "command-git")?.status, "pass");
    assert.equal(checks.find((check) => check.id === "command-npm")?.status, "pass");
    assert.equal(checks.find((check) => check.id === "command-semgrep")?.status, "skip");
  } finally {
    await fs.rm(workspace, { recursive: true, force: true });
  }
});

test("doctor fails npmrc files that reintroduce npm unknown-key warnings", async () => {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-doctor-npmrc-"));
  const bin = path.join(workspace, "bin");
  await fs.mkdir(bin);
  await fs.writeFile(path.join(workspace, ".npmrc"), `${hardenedNpmrc}min-release-age=7\nallow-git=none\n`, "utf8");
  await writeStubExecutable(bin, "git");
  await writeStubExecutable(bin, "npm");

  try {
    const outcome = await runDoctorCommand([], {
      cwd: workspace,
      env: doctorEnv(bin),
      now: () => new Date("2026-05-31T00:00:00.000Z"),
    });

    assert.equal(outcome.result.ok, false);
    assert.equal(outcome.exitCode, 1);
    assert.match(outcome.result.message, /npm-unsupported/);
  } finally {
    await fs.rm(workspace, { recursive: true, force: true });
  }
});

function doctorEnv(bin: string): NodeJS.ProcessEnv {
  return {
    PATH: bin,
    PATHEXT: ".CMD;.EXE;.BAT;.COM",
  };
}

async function writeStubExecutable(directory: string, command: string): Promise<void> {
  const fileName = process.platform === "win32" ? `${command}.cmd` : command;
  const filePath = path.join(directory, fileName);
  const contents = process.platform === "win32" ? "@echo off\r\nexit /b 0\r\n" : "#!/bin/sh\nexit 0\n";
  await fs.writeFile(filePath, contents, "utf8");
  if (process.platform !== "win32") {
    await fs.chmod(filePath, 0o755);
  }
}
