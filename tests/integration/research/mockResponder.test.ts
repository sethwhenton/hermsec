import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runCanonicalAgentDetector } from "../../../src/agent/canonicalHarness.js";
import type { ModelProviderAdapter } from "../../../src/model/provider.js";
import { createDeterministicResearchMockResponder } from "../../../src/research/mockResponder.js";
import {
  OPENROUTER_MODELS_CATALOG_URL,
  sealPricingSnapshot,
} from "../../../src/research/pricing.js";
import { createResearchModelRuntime } from "../../../src/research/runtime.js";

const MODEL = "deepseek/deepseek-v4-flash";
const fixture = path.resolve(
  "tests/fixtures/research/micro-js-vulnerable",
  "project",
);

test("deterministic mock drives the real single-agent tool loop and grounds findings", async () => {
  await withRuntime("single-agent", async (provider) => {
    const result = await runCanonicalAgentDetector({
      repoRoot: fixture,
      mode: "single",
      resolveModel: () => ({
        provider,
        providerConfig: { model: MODEL },
      }),
      runId: "mock-single-tool-loop",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.traces.length, 1);
    assert.equal(result.traces[0]?.rounds, 5);
    assert.equal(result.traces[0]?.toolCalls, 8);
    assert.ok(result.traces[0]?.evidence.length);
    assert.deepEqual(
      new Set(result.findings.flatMap((finding) => finding.cwe ?? [])),
      new Set(["CWE-78", "CWE-79", "CWE-89", "CWE-798"]),
    );
    assert.ok(
      result.findings.every(
        (finding) =>
          finding.agent?.mode === "single-agent" &&
          finding.sourceLocations?.length &&
          finding.agent.candidateIds?.length,
      ),
    );
  });
});

test("deterministic mock preserves moa-low identity through judge and aggregator", async () => {
  await withRuntime("moa-low", async (provider) => {
    const result = await runCanonicalAgentDetector({
      repoRoot: fixture,
      mode: "moa-low",
      resolveModel: () => ({
        provider,
        providerConfig: { model: MODEL },
      }),
      runId: "mock-moa-low",
    });

    assert.equal(
      result.status,
      "completed",
      result.limitations.join("\n"),
    );
    assert.ok(result.candidates.length > 0);
    assert.ok(result.judgments?.length);
    assert.ok(result.groups?.length);
    assert.ok(
      result.findings.every(
        (finding) =>
          finding.agent?.mode === "moa-low" &&
          finding.agent.candidateIds?.length &&
          finding.sourceLocations?.length,
      ),
    );
    assert.ok(
      result.candidates.every(
        (candidate) =>
          candidate.evidenceIds.length > 0 &&
          candidate.sourceLocations.length > 0,
      ),
    );
    assert.ok(
      result.traces
        .filter((trace) => !trace.gapFill)
        .every((trace) => trace.toolCalls > 0),
    );
    const gapFillTraces = result.traces.filter(
      (trace) => trace.gapFill,
    );
    assert.ok(gapFillTraces.length > 0);
    assert.ok(
      gapFillTraces.every(
        (trace) =>
          trace.rounds === 3 &&
          trace.toolCalls === 2 &&
          trace.evidence.length === 2 &&
          trace.evidence.every(
            (evidence) => evidence.qualifiesFinalEvidence,
          ) &&
          trace.evidence.some(
            (evidence) =>
              evidence.toolName === "read_file_snippet" &&
              typeof (evidence.output as { text?: unknown }).text ===
                "string" &&
              ((evidence.output as { text: string }).text.length > 0),
          ),
      ),
    );
    assert.ok(
      result.limitations.every(
        (limitation) =>
          !/per-round tool-call limit|tool calls? per round/iu.test(
            limitation,
          ),
      ),
    );
  });
});

async function withRuntime(
  mode: "single-agent" | "moa-low",
  run: (provider: ModelProviderAdapter) => Promise<void>,
): Promise<void> {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-mock-responder-"),
  );
  try {
    const runtime = createResearchModelRuntime({
      runDirectory: path.join(directory, mode),
      runId: `runtime-${mode}`,
      mode,
      policy: {
        execution: "mock",
        scored: true,
        allowSpend: false,
        noModelFallback: true,
        exactModelAllowlist: [MODEL],
        globalBudgetUsd: 3.25,
        modeBudgetUsd: mode === "single-agent" ? 0.015 : 0.06,
      },
      provider: throwingProvider(),
      pricingSnapshot: sealPricingSnapshot({
        schemaVersion: 2,
        capturedAt: "2026-07-25T00:00:00.000Z",
        source: OPENROUTER_MODELS_CATALOG_URL,
        prices: [
          {
            provider: "openrouter",
            model: MODEL,
            inputUsdPerMillionTokens: 0.0938,
            outputUsdPerMillionTokens: 0.1876,
            contextLength: 1_048_576,
            supportedParameters: ["max_tokens", "tool_choice", "tools"],
          },
        ],
      }),
      mockResponder: createDeterministicResearchMockResponder(),
    });
    await run(runtime.provider);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

function throwingProvider(): ModelProviderAdapter {
  const fail = (): never => {
    throw new Error("mock execution must not contact the provider");
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
