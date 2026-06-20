import assert from "node:assert/strict";
import test from "node:test";
import { routeAgentIntent } from "../../src/agent/intentRouter.js";
import { runAgentTurn } from "../../src/agent/runtime.js";
import type { ModelProviderAdapter, ModelRequest, ProviderConfig, ProviderHealth } from "../../src/model/provider.js";
import type { Finding } from "../../src/shared/types.js";

test("deep-assisted report prompt routes to finding explanation", () => {
  const routed = routeAgentIntent("Deep assisted scan: explain and summarize these scanner findings.");

  assert.equal(routed.intent, "explain_findings");
});

test("forced explanation keeps deep-assisted scan prompts out of scan_target routing", async () => {
  const provider = fakeProvider();
  const result = await runAgentTurn({
    message: "Deep assisted scan: explain these scanner findings.",
    findings: [finding("finding-1", "high")],
    provider,
    providerConfig: { timeoutMs: 10_000 },
    forceIntent: "explain_findings",
  });

  assert.equal(result.intent, "explain_findings");
  assert.equal(result.providerUsed, "openai-compatible");
  assert.equal(result.modelSkippedReason, undefined);
  assert.equal(Object.keys(result.explanations ?? {}).length, 1);
});

test("model explanation chunks and limits large finding sets", async () => {
  const previousLimit = process.env.HERMSEC_MODEL_FINDING_LIMIT;
  const previousChunk = process.env.HERMSEC_MODEL_CHUNK_SIZE;
  process.env.HERMSEC_MODEL_FINDING_LIMIT = "3";
  process.env.HERMSEC_MODEL_CHUNK_SIZE = "2";
  const provider = fakeProvider();

  try {
    const findings = [
      finding("finding-1", "high"),
      finding("finding-2", "medium"),
      finding("finding-3", "medium"),
      finding("finding-4", "low"),
      finding("finding-5", "info"),
    ];
    const result = await runAgentTurn({
      message: "Explain these scanner findings.",
      findings,
      provider,
      providerConfig: { timeoutMs: 10_000 },
      forceIntent: "explain_findings",
    });

    assert.equal(result.providerUsed, "openai-compatible");
    assert.equal(provider.requests.length, 2);
    assert.match(result.message, /top 3 prioritized/);
    assert.equal(Object.keys(result.explanations ?? {}).length, 5);
  } finally {
    restoreEnv("HERMSEC_MODEL_FINDING_LIMIT", previousLimit);
    restoreEnv("HERMSEC_MODEL_CHUNK_SIZE", previousChunk);
  }
});

test("model explanation watchdog falls back when provider stalls", async () => {
  const previousWatchdog = process.env.HERMSEC_MODEL_SUMMARY_WATCHDOG_MS;
  const previousChunk = process.env.HERMSEC_MODEL_CHUNK_TIMEOUT_MS;
  process.env.HERMSEC_MODEL_SUMMARY_WATCHDOG_MS = "1000";
  process.env.HERMSEC_MODEL_CHUNK_TIMEOUT_MS = "1000";

  try {
    const result = await runAgentTurn({
      message: "Explain these scanner findings.",
      findings: [finding("finding-1", "high")],
      provider: fakeProvider({ stall: true }),
      providerConfig: { timeoutMs: 10_000 },
      forceIntent: "explain_findings",
    });

    assert.equal(result.providerUsed, "none");
    assert.equal(result.modelSkippedReason, "model-summary-watchdog");
    assert.equal(Object.keys(result.explanations ?? {}).length, 1);
  } finally {
    restoreEnv("HERMSEC_MODEL_SUMMARY_WATCHDOG_MS", previousWatchdog);
    restoreEnv("HERMSEC_MODEL_CHUNK_TIMEOUT_MS", previousChunk);
  }
});

test("deep-assisted model explanations reject invented evidence and keep fallback text", async () => {
  const result = await runAgentTurn({
    message: "Deep assisted scan: explain these scanner findings.",
    findings: [finding("finding-1", "high")],
    provider: fakeProvider({ inventEvidence: true }),
    providerConfig: { timeoutMs: 10_000 },
    forceIntent: "explain_findings",
  });

  assert.equal(result.intent, "explain_findings");
  assert.equal(result.providerUsed, "openai-compatible");
  assert.match(result.modelSkippedReason ?? "", /unsupported-model-output/);
  assert.match(result.message, /rejected because it was not supported by scanner evidence/);
  assert.doesNotMatch(result.explanations?.["finding-1"]?.evidenceSummary ?? "", /finding-999/);
});

function fakeProvider(options: { stall?: boolean; inventEvidence?: boolean } = {}): ModelProviderAdapter & { requests: ModelRequest[] } {
  const requests: ModelRequest[] = [];
  return {
    id: "openai-compatible",
    requests,
    async listModels() {
      return [{ id: "test-model", local: true }];
    },
    async healthCheck(): Promise<ProviderHealth> {
      return { ok: true, provider: "openai-compatible", message: "ok", local: true };
    },
    async complete(request: ModelRequest, _config?: ProviderConfig) {
      requests.push(request);
      if (options.stall) {
        await new Promise(() => undefined);
      }
      const evidence = JSON.parse(request.messages.at(-1)?.content.match(/Use only this evidence:\n([\s\S]+)$/)?.[1] ?? "[]") as Finding[];
      return {
        provider: "openai-compatible",
        model: "test-model",
        content: JSON.stringify(Object.fromEntries(evidence.map((item) => [
          item.id,
          options.inventEvidence ? inventedExplanationFor(item) : explanationFor(item),
        ]))),
      };
    },
    estimateCost() {
      return { local: true };
    },
  };
}

function finding(id: string, severity: Finding["severity"]): Finding {
  return {
    id,
    title: `Finding ${id}`,
    category: "code",
    severity,
    confidence: "medium",
    description: "Scanner finding.",
    evidence: `src/${id}.js:1 risky pattern`,
    remediation: "Fix the risky pattern.",
    tool: "test-scanner",
    ruleId: "test.rule",
    cwe: ["CWE-79"],
    location: { file: `src/${id}.js`, startLine: 1 },
    fingerprint: `fp-${id}`,
  };
}

function explanationFor(item: Finding) {
  return {
    title: item.title,
    impact: "The scanner evidence indicates a defensive code risk.",
    evidenceSummary: `The scanner reported ${item.location?.file} at line ${item.location?.startLine}.`,
    suggestedFix: "Apply the scanner remediation.",
    confidenceReason: "The explanation uses only the supplied scanner finding.",
    safeNextSteps: ["Review the finding.", "Re-run Hermsec after the fix."],
    cveUsage: "not_present",
  };
}

function inventedExplanationFor(item: Finding) {
  return {
    ...explanationFor(item),
    evidenceSummary: `The scanner reported ${item.location?.file} at line ${item.location?.startLine}, confirmed by semgrep as finding id finding-999 with CWE-89.`,
  };
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
