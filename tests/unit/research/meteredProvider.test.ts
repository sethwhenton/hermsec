import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BudgetExceededError,
  CostKillSwitchError,
  CostLedger,
} from "../../../src/agent/costTracker.js";
import {
  createMeteredProvider,
  createMeteredProviderRuntime,
  UnknownModelUsageError,
} from "../../../src/model/meteredProvider.js";
import type {
  ModelProviderAdapter,
  ModelRequest,
  ModelResponse,
} from "../../../src/model/provider.js";
import type {
  ResearchExecutionMode,
  ResearchExecutionPolicy,
} from "../../../src/research/execution.js";
import {
  createPricingCatalog,
  OPENROUTER_MODELS_CATALOG_URL,
  sealPricingSnapshot,
} from "../../../src/research/pricing.js";
import {
  ReplayCassetteStore,
  replayReferenceFromResponse,
} from "../../../src/research/replay.js";

const MODEL = "deepseek/deepseek-v4-flash";
const TEST_NOW = new Date("2026-07-25T12:00:00.000Z");

test("scored live metering settles authoritative provider cost and exposes reconciliation", async () => {
  await withTempDirectory(async (directory) => {
    const calls: string[] = [];
    const delegate = fakeProvider(async (request) => {
      calls.push("complete");
      return responseFor(
        request,
        { promptTokens: 120, completionTokens: 30 },
        0.000012345,
      );
    });
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const runtime = createMeteredProviderRuntime({
      provider: delegate,
      runId: "live-run",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    const response = await runtime.provider.complete(request());
    const snapshot = await ledger.snapshot();
    const reconciliation = runtime.getLastReconciliation();

    assert.deepEqual(calls, ["complete"]);
    assert.equal(response.usage?.authoritativeUsd, 0.000012345);
    assert.equal(response.usage?.estimatedUsd, 0.000012345);
    assert.equal(snapshot.reservations[0]?.status, "settled");
    assert.equal(snapshot.committedNanoUsd, 12_345);
    assert.equal(snapshot.entries[1]?.costSource, "provider-authoritative");
    assert.equal(reconciliation?.actualNanoUsd, 12_345);
    assert.equal(
      reconciliation?.reservedNanoUsd,
      snapshot.reservations[0]?.reservedNanoUsd,
    );
  });
});

test("scored live dispatch forces exact model for structured requests without tools", async () => {
  await withTempDirectory(async (directory) => {
    const dispatched: ModelRequest[] = [];
    const provider = createMeteredProvider({
      provider: fakeProvider(async (modelRequest) => {
        dispatched.push(modelRequest);
        return responseFor(
          modelRequest,
          { promptTokens: 20, completionTokens: 5 },
          0.00001,
        );
      }),
      runId: "exact-structured-run",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger: new CostLedger(path.join(directory, "cost.jsonl")),
    });

    await provider.complete({
      ...request(),
      requireExactModel: false,
      responseFormat: "json",
    });

    assert.equal(dispatched.length, 1);
    assert.equal(dispatched[0]?.model, MODEL);
    assert.equal(dispatched[0]?.requireExactModel, true);
    assert.equal(dispatched[0]?.tools, undefined);
  });
});

test("live cassette recording binds the ledger to the exact scoped replay reference", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const replayStore = new ReplayCassetteStore(
      path.join(directory, "cassettes"),
      { scopeId: "fixture-digest:harness:prompt:single-agent" },
    );
    const provider = createMeteredProvider({
      provider: fakeProvider(async (modelRequest) =>
        responseFor(
          modelRequest,
          { promptTokens: 24, completionTokens: 8 },
          0.000012,
        ),
      ),
      runId: "recorded-live-run",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      replayStore,
      recordLiveCassettes: true,
    });

    const response = await provider.complete(request());
    const reference = replayReferenceFromResponse(response);
    assert.ok(reference);
    await replayStore.validateReference(reference);

    const snapshot = await ledger.snapshot();
    assert.equal(
      snapshot.reservations[0]?.requestFingerprint,
      reference.requestFingerprint,
    );
    assert.equal(
      snapshot.entries[0]?.requestFingerprint,
      reference.requestFingerprint,
    );
    assert.equal(
      snapshot.entries[1]?.requestFingerprint,
      reference.requestFingerprint,
    );
    assert.ok(reference.scopeIdSha256);
  });
});

test("reservation overspend prevention occurs before provider dispatch", async () => {
  await withTempDirectory(async (directory) => {
    let calls = 0;
    const delegate = fakeProvider(async (modelRequest) => {
      calls += 1;
      return responseFor(
        modelRequest,
        { promptTokens: 10, completionTokens: 10 },
        0.000001,
      );
    });
    const provider = createMeteredProvider({
      provider: delegate,
      runId: "blocked-run",
      mode: "single-agent",
      policy: policy("live", {
        globalBudgetUsd: 0.000001,
        modeBudgetUsd: 0.000001,
      }),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger: new CostLedger(path.join(directory, "cost.jsonl")),
    });

    await assert.rejects(() => provider.complete(request()), BudgetExceededError);
    assert.equal(calls, 0);
  });
});

test("authoritative overage records terminal state and blocks every future dispatch", async () => {
  await withTempDirectory(async (directory) => {
    let calls = 0;
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async (modelRequest) => {
        calls += 1;
        return responseFor(
          modelRequest,
          { promptTokens: 10, completionTokens: 10 },
          0.02,
        );
      }),
      runId: "overage-run",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await assert.rejects(
      () => runtime.provider.complete(request()),
      CostKillSwitchError,
    );
    assert.equal(calls, 1);
    assert.equal(runtime.getLastReconciliation()?.terminal, "overage");
    assert.equal((await ledger.snapshot()).killSwitch.tripped, true);

    await assert.rejects(
      () => runtime.provider.complete(request()),
      CostKillSwitchError,
    );
    assert.equal(calls, 1);
  });
});

test("scored live mode fails closed when authoritative provider cost is missing", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const delegate = fakeProvider(async (modelRequest) =>
      responseFor(
        modelRequest,
        { promptTokens: 20, completionTokens: 5 },
        undefined,
      ),
    );
    const provider = createMeteredProvider({
      provider: delegate,
      runId: "unknown-cost",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await assert.rejects(
      () => provider.complete(request()),
      (error: unknown) =>
        error instanceof UnknownModelUsageError &&
        /authoritative provider cost/i.test(error.message),
    );
    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.reservations[0]?.status, "unknown");
    assert.equal(
      snapshot.committedNanoUsd,
      snapshot.reservations[0]?.reservedNanoUsd,
    );
  });
});

test("scored live mode fails closed when token usage is missing", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const provider = createMeteredProvider({
      provider: fakeProvider(async (modelRequest) => ({
        content: "missing token usage",
        model: modelRequest.model ?? MODEL,
        provider: "openrouter",
        usage: {
          provider: "openrouter",
          model: modelRequest.model ?? MODEL,
          authoritativeUsd: 0.00001,
          local: false,
        },
      })),
      runId: "unknown-usage",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await assert.rejects(() => provider.complete(request()), UnknownModelUsageError);
    assert.equal((await ledger.snapshot()).reservations[0]?.status, "unknown");
  });
});

test("stale catalog fails before any provider method or ledger reservation", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    assert.throws(
      () =>
        createMeteredProvider({
          provider: throwingProvider(),
          runId: "stale-pricing",
          mode: "single-agent",
          policy: policy("live"),
          pricing: pricing(),
          pricingValidation: {
            now: new Date("2026-08-01T00:00:00.000Z"),
            maxAgeMs: 24 * 60 * 60 * 1_000,
          },
          ledger,
        }),
      /stale/i,
    );
    assert.equal((await ledger.snapshot()).entries.length, 0);
  });
});

test("pricing freshness is checked again immediately before each live dispatch", async () => {
  await withTempDirectory(async (directory) => {
    let calls = 0;
    const now = new Date("2026-07-25T12:00:00.000Z");
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const provider = createMeteredProvider({
      provider: fakeProvider(async (modelRequest) => {
        calls += 1;
        return responseFor(
          modelRequest,
          { promptTokens: 10, completionTokens: 5 },
          0.00001,
        );
      }),
      runId: "aging-pricing",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: {
        now,
        maxAgeMs: 24 * 60 * 60 * 1_000,
      },
      ledger,
    });
    now.setUTCDate(28);

    await assert.rejects(() => provider.complete(request()), /stale/i);
    assert.equal(calls, 0);
    assert.equal((await ledger.snapshot()).entries.length, 0);
  });
});

test("exact-model fallback is rejected and conservatively charged unknown", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const provider = createMeteredProvider({
      provider: fakeProvider(async () => ({
        content: "fallback",
        model: "another/model",
        provider: "openrouter",
        usage: {
          provider: "openrouter",
          model: "another/model",
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          authoritativeUsd: 0.00001,
          local: false,
        },
      })),
      runId: "fallback-run",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await assert.rejects(() => provider.complete(request()), /fallback or mismatch/i);
    assert.equal((await ledger.snapshot()).reservations[0]?.status, "unknown");
  });
});

test("provider failure after dispatch remains an unknown committed charge", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const provider = createMeteredProvider({
      provider: fakeProvider(async () => {
        throw new Error("simulated provider timeout");
      }),
      runId: "provider-failure",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await assert.rejects(
      () => provider.complete(request()),
      /simulated provider timeout/i,
    );
    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.reservations[0]?.status, "unknown");
    assert.equal(
      snapshot.committedNanoUsd,
      snapshot.reservations[0]?.reservedNanoUsd,
    );
  });
});

test("unscored live mode may reconcile a clearly labelled pinned estimate", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const provider = createMeteredProvider({
      provider: fakeProvider(async (modelRequest) =>
        responseFor(
          modelRequest,
          { promptTokens: 100, completionTokens: 20 },
          undefined,
        ),
      ),
      runId: "unscored-estimate",
      mode: "single-agent",
      policy: policy("live", { scored: false }),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
    });

    await provider.complete(request());
    assert.equal(
      (await ledger.snapshot()).reservations[0]?.costSource,
      "pinned-token-estimate",
    );
  });
});

test("mock execution never delegates provider or credential health calls", async () => {
  await withTempDirectory(async (directory) => {
    const provider = createMeteredProvider({
      provider: throwingProvider(),
      runId: "mock-run",
      mode: "single-agent",
      policy: policy("mock"),
      pricing: pricing(),
      ledger: new CostLedger(path.join(directory, "cost.jsonl")),
      mockResponder: (modelRequest) =>
        responseFor(
          modelRequest,
          { promptTokens: 0, completionTokens: 0 },
          undefined,
        ),
    });

    const health = await provider.healthCheck({
      apiKeyEnv: "ENV_THAT_MUST_NOT_BE_INSPECTED",
      model: MODEL,
    });
    const models = await provider.listModels({
      apiKeyEnv: "ENV_THAT_MUST_NOT_BE_INSPECTED",
      model: MODEL,
    });
    const response = await provider.complete(
      request(),
      { apiKeyEnv: "ENV_THAT_MUST_NOT_BE_INSPECTED", model: MODEL },
    );

    assert.equal(health.ok, true);
    assert.equal(health.credential, "not-required");
    assert.deepEqual(models.map((model) => model.id), [MODEL]);
    assert.equal(response.content, "fake response");
  });
});

test("replay execution returns persistent cassette without provider or network access", async () => {
  await withTempDirectory(async (directory) => {
    const cassetteDirectory = path.join(directory, "cassettes");
    await new ReplayCassetteStore(cassetteDirectory).record({
      provider: "openrouter",
      model: MODEL,
      request: request(),
      response: responseFor(
        request(),
        { promptTokens: 12, completionTokens: 4 },
        0.000004,
      ),
    });

    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new Error("network must not be called");
    }) as typeof fetch;
    try {
      const provider = createMeteredProvider({
        provider: throwingProvider(),
        runId: "replay-run",
        mode: "single-agent",
        policy: policy("replay"),
        pricing: pricing(),
        ledger: new CostLedger(path.join(directory, "cost.jsonl")),
        replayStore: new ReplayCassetteStore(cassetteDirectory, {
          cursorId: "replay-run",
        }),
      });
      const response = await provider.complete(
        request(),
        { apiKeyEnv: "ENV_THAT_MUST_NOT_BE_INSPECTED", model: MODEL },
      );
      assert.equal(response.content, "fake response");
      assert.equal(response.usage?.totalTokens, 16);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});

function policy(
  execution: ResearchExecutionMode,
  overrides: {
    globalBudgetUsd?: number;
    modeBudgetUsd?: number;
    scored?: boolean;
  } = {},
): ResearchExecutionPolicy {
  return {
    execution,
    scored: overrides.scored ?? true,
    allowSpend: execution === "live",
    noModelFallback: true,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: overrides.globalBudgetUsd ?? 3.25,
    modeBudgetUsd: overrides.modeBudgetUsd ?? 0.015,
  };
}

function pricing() {
  return createPricingCatalog(
    sealPricingSnapshot({
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
          supportedParameters: [
            "max_tokens",
            "response_format",
            "tool_choice",
            "tools",
          ],
        },
      ],
    }),
    [MODEL],
  );
}

function request(): ModelRequest {
  return {
    model: MODEL,
    messages: [{ role: "user", content: "Inspect this fixture." }],
    maxTokens: 100,
    responseFormat: "json",
  };
}

function responseFor(
  modelRequest: ModelRequest,
  usage: { promptTokens: number; completionTokens: number },
  authoritativeUsd: number | undefined,
): ModelResponse {
  return {
    content: "fake response",
    model: modelRequest.model ?? MODEL,
    provider: "openrouter",
    usage: {
      provider: "openrouter",
      model: modelRequest.model ?? MODEL,
      promptTokens: usage.promptTokens,
      completionTokens: usage.completionTokens,
      totalTokens: usage.promptTokens + usage.completionTokens,
      ...(authoritativeUsd !== undefined ? { authoritativeUsd } : {}),
      local: false,
    },
  };
}

function fakeProvider(
  complete: ModelProviderAdapter["complete"],
): ModelProviderAdapter {
  return {
    id: "openrouter",
    capabilities: {
      tools: true,
      jsonResponse: true,
      externalAbort: true,
      streaming: false,
    },
    async listModels() {
      return [{ id: MODEL, local: false, supportsTools: true }];
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
    complete,
  };
}

function throwingProvider(): ModelProviderAdapter {
  const fail = (): never => {
    throw new Error("delegate must not be called");
  };
  return {
    id: "openrouter",
    capabilities: {
      tools: true,
      jsonResponse: true,
      externalAbort: true,
      streaming: false,
    },
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

async function withTempDirectory(
  operation: (directory: string) => Promise<void>,
): Promise<void> {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-metered-provider-"),
  );
  try {
    await operation(directory);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}
