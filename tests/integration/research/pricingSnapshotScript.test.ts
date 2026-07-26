import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import test from "node:test";

test("offline pricing verifier reproduces committed catalog digest", async () => {
  const result = await runProcess(process.execPath, [
    path.resolve("scripts/research/verify-pricing-snapshot.mjs"),
  ]);
  assert.equal(result.code, 0, result.stderr);
  const output = JSON.parse(result.stdout) as {
    valid: boolean;
    digest: string;
    networkRequests: number;
  };
  assert.equal(output.valid, true);
  assert.equal(output.networkRequests, 0);
  assert.equal(
    output.digest,
    "2040f28e700ceab376c9f261b798bbabe18d101fa7d82b696b39ee0fbd5928e7",
  );
});

function runProcess(
  executable: string,
  args: readonly string[],
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
