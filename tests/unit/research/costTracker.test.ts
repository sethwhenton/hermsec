import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BudgetExceededError,
  calculateActualCostNanoUsd,
  calculateActualCostUsd,
  calculateWorstCaseCostNanoUsd,
  calculateWorstCaseCostUsd,
  CostKillSwitchError,
  CostLedger,
  estimatePromptTokenUpperBound,
  nanoUsdToUsd,
  usdToNanoUsd,
} from "../../../src/agent/costTracker.js";

const SCOPE = {
  runId: "run-1",
  mode: "single-agent",
  provider: "openrouter",
  model: "deepseek/deepseek-v4-flash",
};

test("cost calculations use integer nanodollars and conservative rounding", () => {
  const price = {
    inputUsdPerMillionTokens: 0.1,
    outputUsdPerMillionTokens: 0.2,
  };
  const promptUpperBound = estimatePromptTokenUpperBound({
    messages: [{ role: "user", content: "inspect this project" }],
  });
  const reservedNanoUsd = calculateWorstCaseCostNanoUsd(
    promptUpperBound,
    500,
    price,
  );
  const actualNanoUsd = calculateActualCostNanoUsd(40, 20, price);

  assert.ok(promptUpperBound > 40);
  assert.ok(reservedNanoUsd > actualNanoUsd);
  assert.equal(actualNanoUsd, 8_000);
  assert.equal(calculateActualCostUsd(40, 20, price), 0.000008);
  assert.equal(
    calculateWorstCaseCostUsd(promptUpperBound, 500, price),
    nanoUsdToUsd(reservedNanoUsd),
  );
});

test("cost ledger reconciles authoritative cost and releases known failures", async () => {
  await withTempLedger(async (ledger) => {
    const settled = await ledger.reserve({
      ...SCOPE,
      amountUsd: 0.02,
      globalLimitUsd: 0.1,
      modeLimitUsd: 0.05,
      requestFingerprint: "a".repeat(64),
    });
    const reconciliation = await ledger.settle(settled.reservationId, {
      actualUsd: 0.006,
      promptTokens: 10_000,
      completionTokens: 2_000,
      costSource: "provider-authoritative",
    });

    const failed = await ledger.reserve({
      ...SCOPE,
      amountUsd: 0.01,
      globalLimitUsd: 0.1,
      modeLimitUsd: 0.05,
    });
    await ledger.markFailed(failed.reservationId, "Rejected before network dispatch");

    const snapshot = await ledger.snapshot();
    assert.equal(reconciliation.actualNanoUsd, 6_000_000);
    assert.equal(reconciliation.deltaNanoUsd, -14_000_000);
    assert.equal(reconciliation.costSource, "provider-authoritative");
    assert.equal(snapshot.entries.length, 4);
    assert.equal(snapshot.committedNanoUsd, 6_000_000);
    assert.equal(snapshot.committedUsd, 0.006);
    assert.equal(snapshot.reservations[0]?.status, "settled");
    assert.equal(snapshot.reservations[1]?.status, "failed");
    assert.equal(snapshot.reservations[1]?.committedNanoUsd, 0);
  });
});

test("unknown charges keep the full reservation committed and redact reasons", async () => {
  await withTempLedger(async (ledger) => {
    const reservation = await ledger.reserve({
      ...SCOPE,
      runId: "run-unknown",
      mode: "moa-low",
      model: "xiaomi/mimo-v2.5",
      amountUsd: 0.04,
      globalLimitUsd: 0.2,
      modeLimitUsd: 0.1,
    });
    await ledger.markUnknown(
      reservation.reservationId,
      ["Authorization: Bearer sk", "should-be-redacted-1234567890"].join("-"),
    );

    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.committedNanoUsd, 40_000_000);
    assert.equal(snapshot.reservations[0]?.status, "unknown");
    assert.equal(snapshot.reservations[0]?.reason?.includes("sk-should"), false);
    assert.match(snapshot.reservations[0]?.reason ?? "", /\[REDACTED\]/);
  });
});

test("post-response overage is recorded honestly and permanently trips kill switch", async () => {
  await withTempLedger(async (ledger) => {
    const reservation = await ledger.reserve({
      ...SCOPE,
      amountNanoUsd: 10_000_000,
      globalLimitNanoUsd: 15_000_000,
      modeLimitNanoUsd: 15_000_000,
    });
    await assert.rejects(
      () =>
        ledger.settle(reservation.reservationId, {
          actualNanoUsd: 16_000_000,
          promptTokens: 100,
          completionTokens: 10,
          costSource: "provider-authoritative",
        }),
      (error: unknown) =>
        error instanceof CostKillSwitchError &&
        error.reconciliation?.actualNanoUsd === 16_000_000,
    );

    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.killSwitch.tripped, true);
    assert.equal(snapshot.entries.at(-1)?.action, "overage");
    assert.equal(snapshot.committedNanoUsd, 16_000_000);
    assert.deepEqual(snapshot.reservations[0]?.overageReasons, [
      "reservation",
      "global",
      "mode",
    ]);
    await assert.rejects(
      () =>
        ledger.reserve({
          ...SCOPE,
          runId: "later-run",
          amountNanoUsd: 1,
          globalLimitNanoUsd: 1_000_000_000,
          modeLimitNanoUsd: 1_000_000_000,
        }),
      CostKillSwitchError,
    );
    assert.equal((await ledger.snapshot()).entries.length, 2);
  });
});

test("budget boundaries compare exact integer units with no epsilon", async () => {
  await withTempLedger(async (ledger) => {
    await ledger.reserve({
      ...SCOPE,
      amountNanoUsd: 1,
      globalLimitNanoUsd: 1,
      modeLimitNanoUsd: 1,
    });
    await assert.rejects(
      () =>
        ledger.reserve({
          ...SCOPE,
          amountNanoUsd: 1,
          globalLimitNanoUsd: 2,
          modeLimitNanoUsd: 1,
        }),
      (error: unknown) =>
        error instanceof BudgetExceededError &&
        error.budget === "mode" &&
        error.requestedNanoUsd === 1,
    );
    assert.equal(usdToNanoUsd(0.000000001), 1);
  });
});

test("cost ledger detects event tampering", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-cost-tamper-"));
  const ledgerPath = path.join(directory, "cost.jsonl");
  try {
    const ledger = new CostLedger(ledgerPath);
    await ledger.reserve({
      ...SCOPE,
      amountUsd: 0.01,
      globalLimitUsd: 0.1,
      modeLimitUsd: 0.05,
    });
    const content = await fs.readFile(ledgerPath, "utf8");
    await fs.writeFile(
      ledgerPath,
      content.replace('"amountNanoUsd":10000000', '"amountNanoUsd":1000000'),
      "utf8",
    );

    await assert.rejects(() => ledger.snapshot(), /inconsistent|integrity/i);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

async function withTempLedger(
  operation: (ledger: CostLedger) => Promise<void>,
): Promise<void> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-cost-ledger-"));
  try {
    await operation(new CostLedger(path.join(directory, "cost.jsonl")));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}
