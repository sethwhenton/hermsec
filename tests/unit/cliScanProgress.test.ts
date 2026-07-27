import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runScanCommand } from "../../src/cli/commands/scan.js";

test("scan --json streams HERMSEC_PROGRESS JSONL on stderr while returning final JSON outcome", async () => {
  const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermsec-cli-progress-"));
  const progressLines: string[] = [];
  const originalWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array, encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void) => {
    progressLines.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
    if (typeof encodingOrCallback === "function") {
      encodingOrCallback();
    } else {
      callback?.();
    }
    return true;
  }) as typeof process.stderr.write;

  try {
    const outcome = await runScanCommand([
      path.resolve("tests/fixtures/repos/node-express-vulnerable/project"),
      "--mode",
      "offline",
      "--out",
      reportDir,
      "--json",
      "--no-model",
    ], {
      cwd: process.cwd(),
      env: process.env,
      now: () => new Date("2026-06-20T00:00:00.000Z"),
    });

    assert.equal(outcome.json, true);
    assert.equal(outcome.result.ok, true);
    const joined = progressLines.join("");
    assert.match(joined, /^HERMSEC_PROGRESS /m);
    const parsed = joined
      .split(/\r?\n/)
      .filter((line) => line.startsWith("HERMSEC_PROGRESS "))
      .map((line) => JSON.parse(line.slice("HERMSEC_PROGRESS ".length)) as { stage?: string; status?: string });
    assert.equal(parsed.some((event) => event.stage === "scanner" && event.status === "completed"), true);
  } finally {
    process.stderr.write = originalWrite;
    fs.rmSync(reportDir, { recursive: true, force: true });
  }
});
