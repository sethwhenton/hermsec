import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CostLedger } from "../../../src/agent/costTracker.js";

test("cost ledger serializes reservations and settlements across local processes", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-ledger-processes-"));
  const ledgerPath = path.join(directory, "cost.jsonl");
  try {
    const moduleUrl = new URL("../../../src/agent/costTracker.js", import.meta.url).href;
    const workers = Array.from({ length: 12 }, (_, index) => runWorker({
      moduleUrl,
      ledgerPath,
      index,
      amountUsd: 0.01,
      actualUsd: 0.004,
      globalLimitUsd: 1,
      modeLimitUsd: 1,
    }));
    const results = await Promise.all(workers);

    assert.equal(results.every((result) => result.code === 0), true, results.map(formatResult).join("\n"));
    const snapshot = await new CostLedger(ledgerPath).snapshot();
    assert.equal(snapshot.entries.length, 24);
    assert.equal(snapshot.reservations.length, 12);
    assert.equal(snapshot.reservations.every((reservation) => reservation.status === "settled"), true);
    assert.equal(snapshot.committedUsd, 0.048);
    assert.deepEqual(
      snapshot.entries.map((entry) => entry.sequence),
      Array.from({ length: 24 }, (_, index) => index + 1),
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("concurrent reservations cannot race past the global ceiling", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-ledger-ceiling-"));
  const ledgerPath = path.join(directory, "cost.jsonl");
  try {
    const moduleUrl = new URL("../../../src/agent/costTracker.js", import.meta.url).href;
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, index) => runWorker({
        moduleUrl,
        ledgerPath,
        index,
        amountUsd: 0.01,
        globalLimitUsd: 0.05,
        modeLimitUsd: 0.05,
      })),
    );
    const succeeded = results.filter((result) => result.code === 0);
    const budgetBlocked = results.filter((result) => result.code === 3);

    assert.equal(succeeded.length, 5, results.map(formatResult).join("\n"));
    assert.equal(budgetBlocked.length, 5, results.map(formatResult).join("\n"));
    const snapshot = await new CostLedger(ledgerPath).snapshot();
    assert.equal(snapshot.committedUsd, 0.05);
    assert.equal(snapshot.entries.length, 5);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

type WorkerInput = {
  moduleUrl: string;
  ledgerPath: string;
  index: number;
  amountUsd: number;
  actualUsd?: number;
  globalLimitUsd: number;
  modeLimitUsd: number;
};

type WorkerResult = {
  code: number | null;
  stdout: string;
  stderr: string;
};

function runWorker(input: WorkerInput): Promise<WorkerResult> {
  const code = `
    import { BudgetExceededError, CostLedger } from ${JSON.stringify(input.moduleUrl)};
    const ledger = new CostLedger(${JSON.stringify(input.ledgerPath)}, {
      lockTimeoutMs: 20000,
      retryDelayMs: 5
    });
    try {
      const reservation = await ledger.reserve({
        runId: "concurrent-run",
        mode: "single-agent",
        provider: "openrouter",
        model: "deepseek/deepseek-v4-flash",
        amountUsd: ${input.amountUsd},
        globalLimitUsd: ${input.globalLimitUsd},
        modeLimitUsd: ${input.modeLimitUsd},
        requestFingerprint: ${JSON.stringify(String(input.index).padStart(64, "0"))}
      });
      ${
        input.actualUsd === undefined
          ? ""
          : `await ledger.settle(reservation.reservationId, {
              actualUsd: ${input.actualUsd},
              promptTokens: 100,
              completionTokens: 20
            });`
      }
    } catch (error) {
      if (error instanceof BudgetExceededError) {
        process.exitCode = 3;
      } else {
        console.error(error instanceof Error ? error.stack : String(error));
        process.exitCode = 1;
      }
    }
  `;

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", code], {
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
    child.on("close", (exitCode) => {
      resolve({ code: exitCode, stdout, stderr });
    });
  });
}

function formatResult(result: WorkerResult): string {
  return `exit=${result.code} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`;
}
