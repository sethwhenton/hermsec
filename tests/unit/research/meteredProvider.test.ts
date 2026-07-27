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
  createLiveModelCallFailFastGate,
  createMeteredProvider,
  createMeteredProviderRuntime,
  isLiveModelCallFailFastTriggerError,
  meteredRequestFingerprintForRequest,
  meteredRequestFingerprintFromError,
  UnknownModelUsageError,
} from "../../../src/model/meteredProvider.js";
import { createOpenAiCompatibleProvider } from "../../../src/model/openaiCompatible.js";
import {
  ModelProviderRequestError,
  type ProviderConfig,
} from "../../../src/model/provider.js";
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
  createModelCallTraceRecorder,
} from "../../../src/research/modelCallTrace.js";
import {
  fingerprintReplayRequest,
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

test("scored live OpenRouter dispatch replaces caller pricing with immutable sealed ceilings", async () => {
  await withTempDirectory(async (directory) => {
    let dispatchedConfig: ProviderConfig | undefined;
    const callerConfig: ProviderConfig = {
      provider: "openrouter",
      model: MODEL,
      openRouter: {
        allowFallbacks: true,
        maxPrice: {
          prompt: "999",
          completion: "999",
          request: "999",
          image: "999",
          audio: "999",
        },
      },
    };
    const callerSnapshot = JSON.parse(
      JSON.stringify(callerConfig),
    ) as ProviderConfig;
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async (modelRequest, config) => {
        dispatchedConfig = config;
        return responseFor(
          modelRequest,
          { promptTokens: 20, completionTokens: 5 },
          0.00001,
        );
      }),
      runId: "sealed-price-ceiling",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger: new CostLedger(path.join(directory, "cost.jsonl")),
    });

    await runtime.provider.complete(request(), callerConfig);

    assert.deepEqual(dispatchedConfig?.openRouter?.maxPrice, {
      prompt: "0.0938",
      completion: "0.1876",
      request: "0",
    });
    assert.equal(
      Object.hasOwn(dispatchedConfig?.openRouter?.maxPrice ?? {}, "image"),
      false,
    );
    assert.equal(
      Object.hasOwn(dispatchedConfig?.openRouter?.maxPrice ?? {}, "audio"),
      false,
    );
    assert.deepEqual(callerConfig, callerSnapshot);
    assert.notEqual(dispatchedConfig, callerConfig);
    assert.notEqual(dispatchedConfig?.openRouter, callerConfig.openRouter);
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

test("live fail-fast gate aborts dispatched siblings, drains cleanup, and blocks later dispatch", async () => {
  await withTempDirectory(async (directory) => {
    const gate = createLiveModelCallFailFastGate();
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    let dispatches = 0;
    let announceParallelStart!: () => void;
    const parallelStarted = new Promise<void>((resolve) => {
      announceParallelStart = resolve;
    });
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async (modelRequest) => {
        dispatches += 1;
        const prompt = modelRequest.messages[0]?.content ?? "";
        if (prompt === "trigger") {
          await parallelStarted;
          throw new Error("first live provider failure");
        }
        if (prompt === "sibling") {
          announceParallelStart();
          return new Promise<ModelResponse>((_resolve, reject) => {
            const rejectForAbort = () => {
              reject(
                modelRequest.signal?.reason instanceof Error
                  ? modelRequest.signal.reason
                  : Object.assign(
                      new Error("sibling aborted"),
                      { name: "AbortError" },
                    ),
              );
            };
            if (modelRequest.signal?.aborted) {
              rejectForAbort();
              return;
            }
            modelRequest.signal?.addEventListener(
              "abort",
              rejectForAbort,
              { once: true },
            );
          });
        }
        throw new Error("later provider dispatch escaped the gate");
      }),
      runId: "live-fail-fast",
      mode: "moa-low",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      liveFailFastGate: gate,
    });
    const trigger = runtime.provider.complete({
      ...request(),
      messages: [{ role: "user", content: "trigger" }],
    });
    const sibling = runtime.provider.complete({
      ...request(),
      messages: [{ role: "user", content: "sibling" }],
    });

    const [triggerResult, siblingResult] =
      await Promise.allSettled([trigger, sibling]);
    await gate.drain();

    assert.equal(triggerResult.status, "rejected");
    assert.equal(siblingResult.status, "rejected");
    if (
      triggerResult.status !== "rejected" ||
      siblingResult.status !== "rejected"
    ) {
      assert.fail("Both dispatched live calls must reject.");
    }
    assert.equal(
      isLiveModelCallFailFastTriggerError(triggerResult.reason),
      true,
    );
    assert.equal(
      isLiveModelCallFailFastTriggerError(siblingResult.reason),
      false,
    );
    assert.equal(gate.signal.aborted, true);
    assert.equal(dispatches, 2);
    let snapshot = await ledger.snapshot();
    assert.equal(snapshot.reservations.length, 2);
    assert.ok(
      snapshot.reservations.every(
        (reservation) => reservation.status === "unknown",
      ),
    );

    await assert.rejects(
      runtime.provider.complete({
        ...request(),
        messages: [{ role: "user", content: "later" }],
      }),
      (error: unknown) =>
        error instanceof Error && error.name === "AbortError",
    );
    await gate.drain();
    snapshot = await ledger.snapshot();
    assert.equal(dispatches, 2);
    assert.equal(snapshot.reservations.length, 2);
    assert.ok(
      snapshot.reservations.every(
        (reservation) => reservation.status !== "reserved",
      ),
    );
  });
});

test("local request abort trips the live gate before a dispatched provider acknowledges cancellation", async () => {
  await withTempDirectory(async (directory) => {
    const gate = createLiveModelCallFailFastGate();
    const requestController = new AbortController();
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    let announceDispatch!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      announceDispatch = resolve;
    });
    let announceProviderAbort!: () => void;
    const providerObservedAbort = new Promise<void>((resolve) => {
      announceProviderAbort = resolve;
    });
    let releaseProvider!: () => void;
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(
        (modelRequest) =>
          new Promise<ModelResponse>((_resolve, reject) => {
            releaseProvider = () => {
              reject(
                modelRequest.signal?.reason instanceof Error
                  ? modelRequest.signal.reason
                  : Object.assign(
                      new Error("provider cancellation completed"),
                      { name: "AbortError" },
                    ),
              );
            };
            const observeAbort = () => {
              announceProviderAbort();
            };
            if (modelRequest.signal?.aborted) {
              observeAbort();
            } else {
              modelRequest.signal?.addEventListener(
                "abort",
                observeAbort,
                { once: true },
              );
            }
            announceDispatch();
          }),
      ),
      runId: "live-local-abort-latch",
      mode: "moa-low",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      liveFailFastGate: gate,
    });
    const completion = runtime.provider.complete({
      ...request(),
      signal: requestController.signal,
    });
    let settled = false;
    void completion.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );

    await dispatched;
    const timeout = new Error("Bounded inspection loop timed out.");
    requestController.abort(timeout);

    assert.equal(gate.isTripped(), true);
    assert.equal(gate.signal.aborted, true);
    assert.equal(isLiveModelCallFailFastTriggerError(timeout), true);
    await providerObservedAbort;
    assert.equal(settled, false);

    releaseProvider();
    let caught: unknown;
    try {
      await completion;
    } catch (error) {
      caught = error;
    }
    await gate.drain();

    assert.equal(caught, timeout);
    assert.equal(isLiveModelCallFailFastTriggerError(caught), true);
    assert.equal((await ledger.snapshot()).reservations[0]?.status, "unknown");
  });
});

test("local timeout before provider dispatch is a failed trigger with a known-not-charged reservation", async () => {
  await withTempDirectory(async (directory) => {
    const gate = createLiveModelCallFailFastGate();
    const requestController = new AbortController();
    const timeout = new Error("Bounded inspection loop timed out.");
    let dispatches = 0;
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    await fs.mkdir(ledger.lockPath, { recursive: true });
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async (modelRequest) => {
        dispatches += 1;
        return responseFor(
          modelRequest,
          { promptTokens: 1, completionTokens: 1 },
          0.000001,
        );
      }),
      runId: "live-local-abort-before-dispatch",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      liveFailFastGate: gate,
    });
    const recorder = createModelCallTraceRecorder({
      runId: "live-local-abort-before-dispatch",
      mode: "single-agent",
      execution: "live",
      cassettePolicy: "none",
      expectedProvider: "openrouter",
      modelForRole: () => MODEL,
    });
    const provider = recorder.wrapProvider({
      role: "single-agent-inspector",
      gapFill: false,
      provider: runtime.provider,
      providerConfig: {
        provider: "openrouter",
        model: MODEL,
      },
    });

    const completion = provider.complete({
      ...request(),
      signal: requestController.signal,
    });
    requestController.abort(timeout);
    assert.equal(gate.isTripped(), true);
    assert.equal(dispatches, 0);
    await fs.rm(ledger.lockPath, { recursive: true, force: true });

    let caught: unknown;
    try {
      await completion;
    } catch (error) {
      caught = error;
    }

    assert.equal(caught, timeout);
    assert.equal(isLiveModelCallFailFastTriggerError(caught), true);
    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.reservations[0]?.status, "failed");
    assert.equal(snapshot.reservations[0]?.committedNanoUsd, 0);
    const trace = recorder.finalize({
      physical: true,
      detectorStatus: "failed",
      candidateCount: 0,
      requiredSpecialistRoles: ["single-agent-inspector"],
    });
    assert.equal(trace.producerValidation.valid, true);
    assert.equal(trace.calls[0]?.terminalState, "failed");
    assert.equal(trace.calls[0]?.errorCategory, "timeout");
  });
});

test("local timeout after settlement remains a failed trigger without losing authoritative cost", async () => {
  await withTempDirectory(async (directory) => {
    const gate = createLiveModelCallFailFastGate();
    const requestController = new AbortController();
    const timeout = new Error("Bounded inspection loop timed out.");
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async (modelRequest) =>
        responseFor(
          modelRequest,
          { promptTokens: 4, completionTokens: 2 },
          0.000001,
        )),
      runId: "live-local-abort-after-settlement",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      liveFailFastGate: gate,
      onReconciliation: () => {
        requestController.abort(timeout);
      },
    });
    const recorder = createModelCallTraceRecorder({
      runId: "live-local-abort-after-settlement",
      mode: "single-agent",
      execution: "live",
      cassettePolicy: "none",
      expectedProvider: "openrouter",
      modelForRole: () => MODEL,
    });
    const provider = recorder.wrapProvider({
      role: "single-agent-inspector",
      gapFill: false,
      provider: runtime.provider,
      providerConfig: {
        provider: "openrouter",
        model: MODEL,
      },
    });

    let caught: unknown;
    try {
      await provider.complete({
        ...request(),
        signal: requestController.signal,
      });
    } catch (error) {
      caught = error;
    }

    assert.equal(caught, timeout);
    assert.equal(gate.isTripped(), true);
    assert.equal(isLiveModelCallFailFastTriggerError(caught), true);
    const snapshot = await ledger.snapshot();
    assert.equal(snapshot.reservations[0]?.status, "settled");
    assert.equal(snapshot.reservations[0]?.committedNanoUsd, 1_000);
    const trace = recorder.finalize({
      physical: true,
      detectorStatus: "failed",
      candidateCount: 0,
      requiredSpecialistRoles: ["single-agent-inspector"],
    });
    assert.equal(trace.producerValidation.valid, true);
    assert.equal(trace.calls[0]?.terminalState, "failed");
    assert.equal(trace.calls[0]?.errorCategory, "timeout");
  });
});

test("unexpected live provider AbortError is the failed trigger, while mock execution ignores the live gate", async () => {
  await withTempDirectory(async (directory) => {
    const gate = createLiveModelCallFailFastGate();
    const requestController = new AbortController();
    const providerAbort = Object.assign(
      new Error("provider aborted unexpectedly"),
      { name: "AbortError" },
    );
    const live = createMeteredProviderRuntime({
      provider: fakeProvider(async () => {
        requestController.abort(providerAbort);
        throw providerAbort;
      }),
      runId: "unexpected-provider-abort",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger: new CostLedger(path.join(directory, "live-cost.jsonl")),
      liveFailFastGate: gate,
    });

    let caught: unknown;
    try {
      await live.provider.complete({
        ...request(),
        signal: requestController.signal,
      });
    } catch (error) {
      caught = error;
    }
    assert.equal(caught, providerAbort);
    assert.equal(isLiveModelCallFailFastTriggerError(caught), true);
    assert.equal(gate.isTripped(), true);

    const mock = createMeteredProviderRuntime({
      provider: throwingProvider(),
      runId: "mock-ignores-live-gate",
      mode: "single-agent",
      policy: policy("mock"),
      pricing: pricing(),
      ledger: new CostLedger(path.join(directory, "mock-cost.jsonl")),
      liveFailFastGate: gate,
      mockResponder: (modelRequest) =>
        responseFor(
          modelRequest,
          { promptTokens: 0, completionTokens: 0 },
          undefined,
        ),
    });
    assert.equal(
      (await mock.provider.complete(request())).content,
      "fake response",
    );
    assert.equal(
      (await mock.provider.complete(request())).content,
      "fake response",
    );
    assert.equal((await mock.provider.listModels()).length, 1);
  });
});

test("provider failure after dispatch carries its scoped ledger fingerprint into the model trace", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const providerError = Object.freeze(
      new Error("simulated provider timeout"),
    );
    const replayStore = new ReplayCassetteStore(
      path.join(directory, "cassettes"),
      { scopeId: "fixture:harness:prompt:single-agent" },
    );
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async () => {
        throw providerError;
      }),
      runId: "provider-failure",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      replayStore,
      recordLiveCassettes: true,
    });
    const recorder = createModelCallTraceRecorder({
      runId: "provider-failure",
      mode: "single-agent",
      execution: "live",
      cassettePolicy: "recorded",
      expectedProvider: "openrouter",
      modelForRole: () => MODEL,
    });
    const provider = recorder.wrapProvider({
      role: "single-agent-inspector",
      gapFill: false,
      provider: runtime.provider,
      providerConfig: {
        provider: "openrouter",
        model: MODEL,
      },
    });

    let caught: unknown;
    try {
      await provider.complete(request());
    } catch (error) {
      caught = error;
    }
    assert.equal(caught, providerError);
    const snapshot = await ledger.snapshot();
    const authoritativeFingerprint =
      snapshot.reservations[0]?.requestFingerprint;
    assert.ok(authoritativeFingerprint);
    assert.equal(snapshot.reservations[0]?.status, "unknown");
    assert.equal(
      snapshot.committedNanoUsd,
      snapshot.reservations[0]?.reservedNanoUsd,
    );
    assert.equal(
      meteredRequestFingerprintFromError(caught),
      authoritativeFingerprint,
    );
    assert.notEqual(
      authoritativeFingerprint,
      fingerprintReplayRequest({
        provider: "openrouter",
        model: MODEL,
        request: request(),
      }),
    );
    const trace = recorder.finalize({
      physical: true,
      detectorStatus: "degraded",
      candidateCount: 0,
      requiredSpecialistRoles: ["single-agent-inspector"],
    });
    assert.equal(trace.producerValidation.valid, true);
    assert.equal(trace.calls.length, 1);
    assert.equal(trace.calls[0]?.terminalState, "failed");
    assert.equal(trace.calls[0]?.errorCategory, "timeout");
    assert.equal(trace.calls[0]?.fingerprintSource, "metered-replay");
    assert.equal(
      trace.calls[0]?.requestFingerprint,
      authoritativeFingerprint,
    );
    assert.equal(trace.calls[0]?.cassetteReference, undefined);
  });
});

test("trace finalization keeps the scoped fingerprint and canceled state while metered cleanup is pending", async () => {
  await withTempDirectory(async (directory) => {
    const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
    const replayStore = new ReplayCassetteStore(
      path.join(directory, "cassettes"),
      { scopeId: "fixture:harness:prompt:single-agent-canceled" },
    );
    let announceDispatch!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      announceDispatch = resolve;
    });
    let releaseProvider!: () => void;
    const providerRelease = new Promise<void>((resolve) => {
      releaseProvider = resolve;
    });
    const providerAbort = new Error("simulated delayed provider abort");
    providerAbort.name = "AbortError";
    const runtime = createMeteredProviderRuntime({
      provider: fakeProvider(async () => {
        announceDispatch();
        await providerRelease;
        throw providerAbort;
      }),
      runId: "provider-canceled",
      mode: "single-agent",
      policy: policy("live"),
      pricing: pricing(),
      pricingValidation: { now: TEST_NOW },
      ledger,
      replayStore,
      recordLiveCassettes: true,
    });
    const recorder = createModelCallTraceRecorder({
      runId: "provider-canceled",
      mode: "single-agent",
      execution: "live",
      cassettePolicy: "recorded",
      expectedProvider: "openrouter",
      modelForRole: () => MODEL,
    });
    const providerConfig = {
      provider: "openrouter" as const,
      model: MODEL,
    };
    const provider = recorder.wrapProvider({
      role: "single-agent-inspector",
      gapFill: false,
      provider: runtime.provider,
      providerConfig,
    });
    const controller = new AbortController();
    const canceledRequest: ModelRequest = {
      ...request(),
      signal: controller.signal,
    };
    const providerCompletion = provider.complete(
      canceledRequest,
      providerConfig,
    );

    await dispatched;
    const reserved = await ledger.snapshot();
    const authoritativeFingerprint =
      reserved.reservations[0]?.requestFingerprint;
    assert.ok(authoritativeFingerprint);
    assert.equal(reserved.reservations[0]?.status, "reserved");
    assert.equal(
      meteredRequestFingerprintForRequest(
        runtime.provider,
        canceledRequest,
        providerConfig,
      ),
      authoritativeFingerprint,
    );

    controller.abort();
    const earlyTrace = recorder.finalize({
      physical: true,
      detectorStatus: "canceled",
      candidateCount: 0,
      requiredSpecialistRoles: ["single-agent-inspector"],
    });
    assert.equal(earlyTrace.producerValidation.valid, true);
    assert.equal(earlyTrace.calls[0]?.terminalState, "canceled");
    assert.equal(earlyTrace.calls[0]?.errorCategory, "aborted");
    assert.equal(
      earlyTrace.calls[0]?.requestFingerprint,
      authoritativeFingerprint,
    );
    assert.equal(
      earlyTrace.calls[0]?.fingerprintSource,
      "metered-replay",
    );

    releaseProvider();
    await assert.rejects(
      providerCompletion,
      /simulated delayed provider abort/iu,
    );
    const settled = await ledger.snapshot();
    assert.equal(settled.reservations[0]?.status, "unknown");
    const finalTrace = recorder.finalize({
      physical: true,
      detectorStatus: "canceled",
      candidateCount: 0,
      requiredSpecialistRoles: ["single-agent-inspector"],
    });
    assert.equal(finalTrace.calls[0]?.terminalState, "canceled");
    assert.equal(finalTrace.calls[0]?.errorCategory, "aborted");
    assert.equal(
      finalTrace.calls[0]?.requestFingerprint,
      authoritativeFingerprint,
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

test("live adapter failures retain sanitized typed diagnostics, metering, and trace bindings", async () => {
  const cases = [
    {
      name: "http-rate-limit",
      status: 429,
      body: {
        error: {
          code: 429,
          message: "Rate limit exceeded.",
          metadata: {
            error_type: "rate_limit_exceeded",
            provider_code: "rate_limited",
          },
        },
      },
      category: "rate-limit",
      details: {
        status: 429,
        errorType: "rate_limit_exceeded",
        providerCode: "rate_limited",
      },
    },
    {
      name: "embedded-overload",
      status: 200,
      body: {
        model: MODEL,
        choices: [{
          finish_reason: "error",
          message: { content: null },
          error: {
            code: 503,
            message: "Provider overloaded.",
            metadata: { error_type: "provider_overloaded" },
          },
        }],
      },
      category: "provider-unavailable",
      details: {
        status: 503,
        errorType: "provider_overloaded",
      },
    },
    {
      name: "http-provider-unavailable",
      status: 502,
      body: {
        error: {
          code: 502,
          message: "Provider unavailable.",
          metadata: { error_type: "provider_unavailable" },
        },
      },
      category: "provider-unavailable",
      details: {
        status: 502,
        errorType: "provider_unavailable",
      },
    },
    {
      name: "inferred-timeout",
      status: 504,
      body: {
        error: {
          code: 504,
          message: "Request aborted due to timeout.",
        },
      },
      category: "timeout",
      details: {
        status: 504,
        errorType: "timeout",
      },
    },
    {
      name: "price-filter-prose-only",
      status: 404,
      body: {
        error: {
          code: 404,
          message: "No allowed providers are available.",
        },
      },
      category: "provider",
      details: {
        status: 404,
      },
    },
    {
      name: "price-filter-typed",
      status: 404,
      body: {
        error: {
          code: 404,
          message: "No allowed providers are available.",
          metadata: {
            error_type: "provider_unavailable",
          },
        },
      },
      category: "provider-unavailable",
      details: {
        status: 404,
        errorType: "provider_unavailable",
      },
    },
    {
      name: "ordinary-not-found",
      status: 404,
      body: {
        error: {
          code: 404,
          message: "Model not found.",
        },
      },
      category: "provider",
      details: {
        status: 404,
      },
    },
    {
      name: "conflicting-structured-rate-status",
      status: 429,
      body: {
        error: {
          code: 429,
          message: "Invalid request.",
          metadata: {
            error_type: "invalid_request",
          },
        },
      },
      category: "provider",
      details: {
        status: 429,
        errorType: "invalid_request",
      },
    },
  ] as const;

  const previousFetch = globalThis.fetch;
  try {
    for (const candidate of cases) {
      await withTempDirectory(async (directory) => {
        globalThis.fetch = (async () =>
          new Response(JSON.stringify(candidate.body), {
            status: candidate.status,
          })) as typeof fetch;
        const runId = `provider-category-${candidate.name}`;
        const ledger = new CostLedger(path.join(directory, "cost.jsonl"));
        const replayStore = new ReplayCassetteStore(
          path.join(directory, "cassettes"),
          { scopeId: `fixture:harness:prompt:${candidate.name}` },
        );
        const adapter = createOpenAiCompatibleProvider({
          id: "openrouter",
          baseUrl: "https://openrouter.example/api/v1",
          models: [MODEL],
          local: true,
        });
        const runtime = createMeteredProviderRuntime({
          provider: adapter,
          runId,
          mode: "single-agent",
          policy: policy("live"),
          pricing: pricing(),
          pricingValidation: { now: TEST_NOW },
          ledger,
          replayStore,
          recordLiveCassettes: true,
        });
        const recorder = createModelCallTraceRecorder({
          runId,
          mode: "single-agent",
          execution: "live",
          cassettePolicy: "recorded",
          expectedProvider: "openrouter",
          modelForRole: () => MODEL,
        });
        const provider = recorder.wrapProvider({
          role: "single-agent-inspector",
          gapFill: false,
          provider: runtime.provider,
          providerConfig: {
            provider: "openrouter",
            model: MODEL,
          },
        });

        let caught: unknown;
        try {
          await provider.complete(request());
        } catch (error) {
          caught = error;
        }
        assert.ok(caught instanceof ModelProviderRequestError);
        const snapshot = await ledger.snapshot();
        const reservation = snapshot.reservations[0];
        assert.equal(reservation?.status, "unknown");
        assert.equal(
          meteredRequestFingerprintFromError(caught),
          reservation?.requestFingerprint,
        );
        const trace = recorder.finalize({
          physical: true,
          detectorStatus: "failed",
          candidateCount: 0,
          requiredSpecialistRoles: ["single-agent-inspector"],
        });
        assert.equal(trace.producerValidation.valid, true);
        assert.equal(trace.calls.length, 1);
        assert.equal(trace.calls[0]?.terminalState, "failed");
        assert.equal(trace.calls[0]?.errorCategory, candidate.category);
        assert.deepEqual(trace.calls[0]?.providerError, candidate.details);
        assert.equal(trace.calls[0]?.fingerprintSource, "metered-replay");
        assert.equal(
          trace.calls[0]?.requestFingerprint,
          reservation?.requestFingerprint,
        );
        assert.equal(trace.calls[0]?.cassetteReference, undefined);
      });
    }
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("transport timeout stays failed and timeout-classified through metering and trace", async () => {
  await withTempDirectory(async (directory) => {
    const previousFetch = globalThis.fetch;
    try {
      globalThis.fetch = ((_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          assert.ok(signal);
          const rejectWithReason = () => {
            reject(
              signal.reason ??
                new DOMException(
                  "The operation timed out.",
                  "TimeoutError",
                ),
            );
          };
          if (signal.aborted) {
            rejectWithReason();
          } else {
            signal.addEventListener("abort", rejectWithReason, {
              once: true,
            });
          }
        })) as typeof fetch;
      const runId = "provider-transport-timeout";
      const ledger = new CostLedger(
        path.join(directory, "cost.jsonl"),
      );
      const runtime = createMeteredProviderRuntime({
        provider: createOpenAiCompatibleProvider({
          id: "openrouter",
          baseUrl: "https://openrouter.example/api/v1",
          models: [MODEL],
          local: true,
        }),
        runId,
        mode: "single-agent",
        policy: policy("live"),
        pricing: pricing(),
        pricingValidation: { now: TEST_NOW },
        ledger,
      });
      const recorder = createModelCallTraceRecorder({
        runId,
        mode: "single-agent",
        execution: "live",
        cassettePolicy: "none",
        expectedProvider: "openrouter",
        modelForRole: () => MODEL,
      });
      const provider = recorder.wrapProvider({
        role: "single-agent-inspector",
        gapFill: false,
        provider: runtime.provider,
        providerConfig: {
          provider: "openrouter",
          model: MODEL,
        },
      });
      const providerConfig: ProviderConfig = {
        provider: "openrouter",
        model: MODEL,
        timeoutMs: 5,
      };

      let caught: unknown;
      try {
        await provider.complete(request(), providerConfig);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught instanceof ModelProviderRequestError);
      assert.equal(caught.errorType, "timeout");
      const snapshot = await ledger.snapshot();
      assert.equal(snapshot.reservations[0]?.status, "unknown");
      const trace = recorder.finalize({
        physical: true,
        detectorStatus: "degraded",
        candidateCount: 0,
        requiredSpecialistRoles: ["single-agent-inspector"],
      });
      assert.equal(trace.producerValidation.valid, true);
      assert.equal(trace.calls[0]?.terminalState, "failed");
      assert.equal(trace.calls[0]?.errorCategory, "timeout");
      assert.deepEqual(trace.calls[0]?.providerError, {
        errorType: "timeout",
      });
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
