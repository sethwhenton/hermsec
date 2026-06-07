import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";

const require = createRequire(import.meta.url);

test("Electron desktop boots the renderer bridge and runs a live scan smoke test", async () => {
  const electronPath = require("electron") as string;
  const mainPath = path.resolve("dist/src/desktop/main.js");
  const result = await runElectronSmoke(electronPath, mainPath);
  assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
});

function runElectronSmoke(electronPath: string, mainPath: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(electronPath, [mainPath, "--smoke"], {
      env: {
        ...process.env,
        HERMSEC_MODEL_PROVIDER: "none",
        HERMSEC_ALLOW_REMOTE_PROVIDERS: "false",
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
