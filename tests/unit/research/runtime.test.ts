import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CostKillSwitchError } from "../../../src/agent/costTracker.js";
import type { ModelProviderAdapter } from "../../../src/model/provider.js";
import { OPENROUTER_MODELS_CATALOG_URL, sealPricingSnapshot } from "../../../src/research/pricing.js";
import {
  createResearchModelRuntime,
  createResearchModelSuiteRuntime,
  type CreateResearchModelRunInput,
  type CreateResearchModelRuntimeInput,
} from "../../../src/research/runtime.js";

const MODEL = "deepseek/deepseek-v4-flash";

test("research runtime exposes provider, ledger, replay, and pricing provenance without credentials", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-runtime-"));
  try {
    const runtime = createResearchModelRuntime({
      runDirectory: path.join(directory, "run"),
      replayDirectory: path.join(directory, "cassettes"),
      runId: "mock-run",
      mode: "single-agent",
      policy: {
        execution: "mock",
        scored: true,
        allowSpend: false,
        noModelFallback: true,
        exactModelAllowlist: [MODEL],
        globalBudgetUsd: 3.25,
        modeBudgetUsd: 0.015,
      },
      provider: throwingProvider(),
      pricingSnapshot: snapshot(),
      mockResponder: (request) => ({
        content: "mock",
        model: request.model ?? MODEL,
        provider: "openrouter",
      }),
    });

    const result = await runtime.provider.complete({
      model: MODEL,
      messages: [{ role: "user", content: "Inspect fixture." }],
      maxTokens: 50,
    });
    assert.equal(result.content, "mock");
    assert.equal(runtime.provenance.execution, "mock");
    assert.equal(
      runtime.provenance.pricingCatalogDigestSha256,
      snapshot().catalogDigestSha256,
    );
    assert.ok(runtime.replayStore);
    assert.equal((await runtime.ledger.snapshot()).entries.length, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("direct runtime snapshots policy before caller mutation", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-runtime-policy-snapshot-"),
  );
  let liveDispatches = 0;
  const policy = {
    execution: "mock" as "mock" | "live",
    scored: true,
    allowSpend: false,
    noModelFallback: true as const,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: 3.25,
    modeBudgetUsd: 0.015,
  };
  try {
    const runtime = createResearchModelRuntime({
      runDirectory: path.join(directory, "run"),
      runId: "policy-snapshot-mock",
      mode: "single-agent",
      policy,
      provider: liveProvider(0.00001, () => {
        liveDispatches += 1;
      }),
      pricingSnapshot: snapshot(),
      mockResponder: (request) => ({
        content: "mock snapshot",
        model: request.model ?? MODEL,
        provider: "openrouter",
      }),
    });

    policy.execution = "live";
    policy.scored = false;
    policy.allowSpend = true;
    policy.globalBudgetUsd = 100;
    policy.modeBudgetUsd = 100;
    policy.exactModelAllowlist.splice(0, 1, "unapproved/model");

    const response = await runtime.provider.complete({
      model: MODEL,
      messages: [{ role: "user", content: "Use the immutable policy." }],
      maxTokens: 20,
    });
    assert.equal(response.content, "mock snapshot");
    assert.equal(liveDispatches, 0);
    assert.equal((await runtime.ledger.snapshot()).entries.length, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("direct runtime reads a stateful policy accessor only once", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-runtime-policy-accessor-"),
  );
  let executionReads = 0;
  let liveDispatches = 0;
  const policy = {
    get execution() {
      executionReads += 1;
      return executionReads === 1 ? ("mock" as const) : ("live" as const);
    },
    scored: true,
    allowSpend: false,
    noModelFallback: true as const,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: 3.25,
    modeBudgetUsd: 0.015,
  };
  try {
    const runtime = createResearchModelRuntime({
      runDirectory: path.join(directory, "run"),
      runId: "accessor-policy-mock",
      mode: "single-agent",
      policy,
      provider: liveProvider(0.00001, () => {
        liveDispatches += 1;
      }),
      pricingSnapshot: snapshot(),
      mockResponder: (request) => ({
        content: "accessor mock",
        model: request.model ?? MODEL,
        provider: "openrouter",
      }),
    });
    const response = await runtime.provider.complete({
      model: MODEL,
      messages: [{ role: "user", content: "Do not cross the live boundary." }],
      maxTokens: 20,
    });

    assert.equal(response.content, "accessor mock");
    assert.equal(runtime.provenance.execution, "mock");
    assert.equal(executionReads, 1);
    assert.equal(liveDispatches, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("suite runtime snapshots live policy and its nested allowlist", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-suite-policy-snapshot-"),
  );
  const policy = livePolicy();
  let dispatches = 0;
  try {
    const suite = createResearchModelSuiteRuntime({
      suiteId: `policy-${path.basename(directory)}`,
      suiteDirectory: path.join(directory, "suite"),
    });
    const runtime = suite.createRun({
      runDirectory: path.join(directory, "runs", "one"),
      runId: "immutable-live-run",
      mode: "single-agent",
      policy,
      provider: liveProvider(0.00001, () => {
        dispatches += 1;
      }),
      pricingSnapshot: snapshot(),
      pricingValidation: {
        now: new Date("2026-07-25T12:00:00.000Z"),
      },
    });

    policy.scored = false;
    policy.globalBudgetUsd = 100;
    policy.modeBudgetUsd = 100;
    policy.exactModelAllowlist.splice(0, 1, "unapproved/model");

    await runtime.provider.complete({
      model: MODEL,
      messages: [{ role: "user", content: "Use the immutable live policy." }],
      maxTokens: 20,
    });
    const ledger = await runtime.ledger.snapshot();
    assert.equal(dispatches, 1);
    assert.equal(ledger.reservations[0]?.globalLimitUsd, 3.25);
    assert.equal(ledger.reservations[0]?.modeLimitUsd, 0.015);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("suite runtime uses one policy snapshot for containment and dispatch", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-suite-policy-accessor-"),
  );
  let executionReads = 0;
  let liveDispatches = 0;
  const policy = {
    get execution() {
      executionReads += 1;
      return executionReads === 1 ? ("mock" as const) : ("live" as const);
    },
    scored: true,
    allowSpend: false,
    noModelFallback: true as const,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: 3.25,
    modeBudgetUsd: 0.015,
  };
  try {
    const suiteDirectory = path.join(directory, "suite");
    const suite = createResearchModelSuiteRuntime({
      suiteId: `accessor-${path.basename(directory)}`,
      suiteDirectory,
    });
    const runtime = suite.createRun({
      runDirectory: suiteDirectory,
      runId: "suite-accessor-mock",
      mode: "single-agent",
      policy,
      provider: liveProvider(0.00001, () => {
        liveDispatches += 1;
      }),
      pricingSnapshot: snapshot(),
      mockResponder: (request) => ({
        content: "suite accessor mock",
        model: request.model ?? MODEL,
        provider: "openrouter",
      }),
    });
    const response = await runtime.provider.complete({
      model: MODEL,
      messages: [{ role: "user", content: "Remain mock." }],
      maxTokens: 20,
    });

    assert.equal(response.content, "suite accessor mock");
    assert.equal(runtime.provenance.execution, "mock");
    assert.equal(executionReads, 1);
    assert.equal(liveDispatches, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("suite runtime shares one live fail-fast gate across runs and drains all ledger cleanup", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-suite-live-fail-fast-"),
  );
  let dispatchesA = 0;
  let dispatchesB = 0;
  try {
    const suite = createResearchModelSuiteRuntime({
      suiteId: `live-fail-fast-${path.basename(directory)}`,
      suiteDirectory: path.join(directory, "suite"),
    });
    const runtimeA = suite.createRun({
      runDirectory: path.join(directory, "runs", "a"),
      runId: "live-fail-fast-a",
      mode: "single-agent",
      policy: livePolicy(),
      provider: {
        ...liveProvider(0.00001, () => undefined),
        async complete() {
          dispatchesA += 1;
          throw new Error("run A provider failure");
        },
      },
      pricingSnapshot: snapshot(),
      pricingValidation: {
        now: new Date("2026-07-25T12:00:00.000Z"),
      },
    });
    const runtimeB = suite.createRun({
      runDirectory: path.join(directory, "runs", "b"),
      runId: "live-fail-fast-b",
      mode: "moa-low",
      policy: livePolicy(),
      provider: liveProvider(0.00001, () => {
        dispatchesB += 1;
      }),
      pricingSnapshot: snapshot(),
      pricingValidation: {
        now: new Date("2026-07-25T12:00:00.000Z"),
      },
    });

    await assert.rejects(
      runtimeA.provider.complete({
        model: MODEL,
        messages: [{ role: "user", content: "Fail run A." }],
        maxTokens: 20,
      }),
      /run A provider failure/u,
    );
    await suite.liveFailFastGate.drain();
    await assert.rejects(
      runtimeB.provider.complete({
        model: MODEL,
        messages: [{ role: "user", content: "Do not dispatch run B." }],
        maxTokens: 20,
      }),
      (error: unknown) =>
        error instanceof Error && error.name === "AbortError",
    );
    await suite.liveFailFastGate.drain();

    const ledger = await suite.ledger.snapshot();
    assert.equal(dispatchesA, 1);
    assert.equal(dispatchesB, 0);
    assert.equal(ledger.reservations.length, 1);
    assert.equal(ledger.reservations[0]?.status, "unknown");
    assert.ok(
      ledger.reservations.every(
        (reservation) => reservation.status !== "reserved",
      ),
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("suite runtime rejects divergent ledgers and overage A fail-fast blocks distinct run B", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-runtime-shared-ledger-"),
  );
  const suiteDirectory = path.join(directory, "suite");
  const suiteId = `suite-${path.basename(directory)}`;
  const runA = path.join(directory, "runs", "run-a");
  const runB = path.join(directory, "runs", "run-b");
  let dispatchesA = 0;
  let dispatchesB = 0;

  try {
    assert.throws(
      () =>
        createResearchModelRuntime({
          runDirectory: runA,
          sharedLedgerPath: path.join(directory, "suite-a.jsonl"),
          runId: "direct-live-run",
          mode: "single-agent",
          policy: livePolicy(),
          provider: liveProvider(0.00001, () => {
            dispatchesA += 1;
          }),
          pricingSnapshot: snapshot(),
          pricingValidation: {
            now: new Date("2026-07-25T12:00:00.000Z"),
          },
        } as unknown as CreateResearchModelRuntimeInput),
      /must be created through createResearchModelSuiteRuntime/i,
    );

    const suite = createResearchModelSuiteRuntime({
      suiteId,
      suiteDirectory,
    });
    assert.throws(
      () =>
        createResearchModelSuiteRuntime({
          suiteId,
          suiteDirectory: path.join(directory, "divergent-suite"),
        }),
      /already bound to a different global cost ledger/i,
    );
    assert.throws(
      () =>
        suite.createRun({
          runDirectory: runA,
          sharedLedgerPath: path.join(directory, "suite-b.jsonl"),
          runId: "run-ledger-override",
          mode: "single-agent",
          policy: livePolicy(),
          provider: liveProvider(0.00001, () => {
            dispatchesA += 1;
          }),
          pricingSnapshot: snapshot(),
          pricingValidation: {
            now: new Date("2026-07-25T12:00:00.000Z"),
          },
        } as unknown as CreateResearchModelRunInput),
      /cannot select or override the suite cost ledger/i,
    );

    const runtimeA = suite.createRun({
      runDirectory: runA,
      runId: "live-run-a",
      mode: "single-agent",
      policy: livePolicy(),
      provider: liveProvider(0.02, () => {
        dispatchesA += 1;
      }),
      pricingSnapshot: snapshot(),
      pricingValidation: {
        now: new Date("2026-07-25T12:00:00.000Z"),
      },
    });
    const runtimeB = suite.createRun({
      runDirectory: runB,
      runId: "live-run-b",
      mode: "single-agent",
      policy: livePolicy(),
      provider: liveProvider(0.00001, () => {
        dispatchesB += 1;
      }),
      pricingSnapshot: snapshot(),
      pricingValidation: {
        now: new Date("2026-07-25T12:00:00.000Z"),
      },
    });

    assert.notEqual(runtimeA.runDirectory, runtimeB.runDirectory);
    assert.equal(
      runtimeA.ledger.filePath,
      path.resolve(suiteDirectory, "cost-ledger.jsonl"),
    );
    assert.equal(runtimeB.ledger.filePath, runtimeA.ledger.filePath);
    assert.equal(runtimeA.provenance.suiteId, suiteId);
    assert.equal(runtimeB.provenance.suiteId, suiteId);

    await assert.rejects(
      () =>
        runtimeA.provider.complete({
          model: MODEL,
          messages: [{ role: "user", content: "Inspect run A." }],
          maxTokens: 50,
        }),
      CostKillSwitchError,
    );
    await assert.rejects(
      () =>
        runtimeB.provider.complete({
          model: MODEL,
          messages: [{ role: "user", content: "Inspect run B." }],
          maxTokens: 50,
        }),
      (error: unknown) =>
        error instanceof Error && error.name === "AbortError",
    );
    assert.equal(dispatchesA, 1);
    assert.equal(dispatchesB, 0);
    assert.equal((await runtimeB.ledger.snapshot()).killSwitch.tripped, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

function snapshot() {
  return sealPricingSnapshot({
    schemaVersion: 2,
    capturedAt: "2026-07-25T00:00:00.000Z",
    source: OPENROUTER_MODELS_CATALOG_URL,
    prices: [
      {
        provider: "openrouter",
        model: MODEL,
        inputUsdPerMillionTokens: 0.0938,
        outputUsdPerMillionTokens: 0.1876,
        contextLength: 1048576,
        supportedParameters: ["max_tokens", "tool_choice", "tools"],
      },
    ],
  });
}

function livePolicy() {
  return {
    execution: "live" as const,
    scored: true,
    allowSpend: true,
    noModelFallback: true as const,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: 3.25,
    modeBudgetUsd: 0.015,
  };
}

function liveProvider(
  authoritativeUsd: number,
  onDispatch: () => void,
): ModelProviderAdapter {
  return {
    id: "openrouter",
    async listModels() {
      return [{ id: MODEL, local: false }];
    },
    async healthCheck() {
      return {
        ok: true,
        provider: "openrouter",
        message: "fake",
        credential: "env-present",
        local: false,
      };
    },
    async complete(request) {
      onDispatch();
      return {
        content: "fake live response",
        model: request.model ?? MODEL,
        provider: "openrouter",
        usage: {
          provider: "openrouter",
          model: request.model ?? MODEL,
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          authoritativeUsd,
          local: false,
        },
      };
    },
  };
}

function throwingProvider(): ModelProviderAdapter {
  const fail = (): never => {
    throw new Error("provider must not be inspected in mock execution");
  };
  return {
    id: "openrouter",
    async listModels() {
      return fail();
    },
    async healthCheck() {
      return fail();
    },
    async complete() {
      return fail();
    },
  };
}
