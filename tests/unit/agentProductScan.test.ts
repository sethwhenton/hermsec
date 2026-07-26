import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCodeInspectionRuntime } from "../../src/agent/codeInspection.js";
import { runProductAgentScan } from "../../src/agent/productScan.js";
import { assistModeFrom } from "../../src/core/progress.js";
import { noModelProvider } from "../../src/model/noModel.js";
import type { ModelProviderAdapter, ModelRequest, ProviderConfig, ProviderHealth } from "../../src/model/provider.js";
import type { Finding } from "../../src/shared/types.js";

const lowSpecialistIds = ["injection-and-execution", "auth-and-data-flow", "secrets-and-config"];
const highSpecialistIds = [...lowSpecialistIds, "database-and-storage", "config-and-iac"];
const judgeAndAggregatorIds = ["moa-false-positive-judge", "moa-aggregator"];
const productAgentPanelEnvNames = [
  "HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT",
  "HERMSEC_PRODUCT_AGENT_PANEL",
  "HERMSEC_PRODUCT_AGENT_PROFILE",
  "HERMSEC_MOA_PANEL_PROFILE",
] as const;

test("assist mode normalization maps legacy input to canonical modes", () => {
  assert.equal(assistModeFrom("scanner-model-summary"), "scanner-only");
  assert.equal(assistModeFrom(undefined), "scanner-only");
  assert.equal(assistModeFrom("single-agent"), "single-agent");
  assert.equal(assistModeFrom("moa-assisted"), "moa-low");
  assert.equal(assistModeFrom("scanner-moa-assisted"), "scanner-moa-low");
});

test("code inspection helpers stay inside the repo and bounded source set", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  assert.deepEqual(runtime.listFiles().map((file) => file.path), ["src/app.js"]);

  const search = await runtime.searchCode({ query: "eval(" });
  assert.equal(search.matches[0]?.file, "src/app.js");
  assert.equal(search.matches[0]?.line, 1);

  const snippet = await runtime.readFileSnippet({ path: "src/app.js", startLine: 1, endLine: 1 });
  assert.match(snippet.text, /eval/);

  await assert.rejects(
    () => runtime.readFileSnippet({ path: "../outside.js" }),
    /outside the allowed source set|escapes the repository root/,
  );
  await assert.rejects(
    () => runtime.readFileSnippet({ path: "node_modules/pkg/index.js" }),
    /outside the allowed source set/,
  );
});

test("single-agent mode fails clearly without a model provider", async () => {
  const repo = await fixtureRepo();
  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "single-agent",
    provider: noModelProvider,
  });

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.errorCode, "MODEL_PROVIDER_REQUIRED");
    assert.match(result.message, /requires an enabled model provider/);
  }
});

test("single-agent mode normalizes validated model findings", async () => {
  const repo = await fixtureRepo();
  const reportOutputDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-agent-report-"));
  const progress: Array<{ stage?: string; id?: string; status?: string }> = [];
  const provider = fakeProvider((request) => findingResponse(firstPromptCandidateId(request) ?? "missing-candidate"));
  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "single-agent",
    provider,
    providerConfig: { timeoutMs: 10_000 },
    reportOutputDirectory,
    onProgress: (event) => progress.push(event),
  });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.tool, "hermsec-agent");
    assert.equal(result.findings[0]?.location?.file, "src/app.js");
    assert.equal(result.findings[0]?.agent?.source, "single-agent");
    assert.equal(result.findings[0]?.agent?.provider, "openai-compatible");
    assert.equal(result.agentMode.checkpointResumed, false);
    assert.match(result.agentMode.checkpointPath ?? "", /\.checkpoints/);
    assert.ok(progress.some((event) => event.stage === "candidate" && event.status === "completed"));
    assert.ok(progress.some((event) => event.stage === "task" && event.status === "completed"));
    assert.ok(progress.some((event) => event.stage === "revalidation" && event.status === "completed"));
    assert.doesNotMatch(provider.requests[0]?.messages.at(-1)?.content ?? "", /scannerFindings|scanner-confirmed|scanner results/i);
  }
});

test("moa-assisted mode runs specialists, judge, and aggregator", async () => {
  const repo = await fixtureRepo();
  const provider = fakeMoaProvider();

  const result = await withProductAgentPanelEnv({}, () =>
    runProductAgentScan({
      repoRoot: repo,
      mode: "moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000 },
    }),
  );

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 3);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.tool, "hermsec-moa");
    assert.equal(result.findings[0]?.agent?.source, "moa-aggregator");
    assert.equal(result.findings[0]?.agent?.judge?.reviewedBy, "moa-false-positive-judge");
    assert.ok(result.findings[0]?.agent?.sourceFindingIds?.[0]?.startsWith("candidate-"));
    assert.deepEqual(result.agentMode.agentsUsed, [...lowSpecialistIds, ...judgeAndAggregatorIds]);
    assert.deepEqual(result.agentMode.agents?.map((agent) => agent.id), ["injection-and-execution", ...judgeAndAggregatorIds]);
    for (const request of provider.requests) {
      assert.doesNotMatch(request.messages.at(-1)?.content ?? "", /scannerFindings|scanner-confirmed|scanner results/i);
    }
  }
});

test("moa-assisted low-count panel routes only active role model selections", async () => {
  const repo = await fixtureRepo();
  const provider = fakeMoaProvider();
  const roleModels = new Map([
    ["injection-and-execution", "model-injection"],
    ["auth-and-data-flow", "model-auth"],
    ["secrets-and-config", "model-secrets"],
    ["database-and-storage", "model-database"],
    ["config-and-iac", "model-iac"],
    ["moa-false-positive-judge", "model-judge"],
    ["moa-aggregator", "model-aggregator"],
  ]);
  const resolvedRoles: string[] = [];

  const result = await withProductAgentPanelEnv(
    { HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT: "1", HERMSEC_PRODUCT_AGENT_PANEL: "low" },
    () => runProductAgentScan({
      repoRoot: repo,
      mode: "moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000, model: "fallback-model" },
      modelResolver: async (roleId) => {
        resolvedRoles.push(roleId);
        return {
          provider,
          providerConfig: { timeoutMs: 10_000, model: roleModels.get(roleId) ?? "fallback-model" },
        };
      },
    }),
  );

  assert.equal(result.ok, true);
  assert.deepEqual(resolvedRoles, ["injection-and-execution", ...judgeAndAggregatorIds]);
  assert.deepEqual(provider.configs.map((config) => config?.model), [
    "model-injection",
    "model-judge",
    "model-aggregator",
  ]);
  if (result.ok) {
    assert.ok(result.agentMode.agents);
    const models = result.agentMode.agents.map((agent) => agent.model);
    assert.deepEqual(models, [
      "model-injection",
      "model-judge",
      "model-aggregator",
    ]);
    assert.deepEqual(result.agentMode.agentsUsed, ["injection-and-execution", ...judgeAndAggregatorIds]);
    assert.equal(result.agentMode.candidateFindingCount, 1);
  }
});

test("moa-assisted high panel expands specialists and routes each configured model", async () => {
  const repo = await fixtureRepo();
  const provider = fakeMoaProvider();
  const roleModels = new Map([
    ["injection-and-execution", "model-injection"],
    ["auth-and-data-flow", "model-auth"],
    ["secrets-and-config", "model-secrets"],
    ["database-and-storage", "model-database"],
    ["config-and-iac", "model-iac"],
    ["moa-false-positive-judge", "model-judge"],
    ["moa-aggregator", "model-aggregator"],
  ]);
  const resolvedRoles: string[] = [];

  const result = await withProductAgentPanelEnv({ HERMSEC_PRODUCT_AGENT_PANEL: "high" }, () =>
    runProductAgentScan({
      repoRoot: repo,
      mode: "moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000, model: "fallback-model" },
      modelResolver: async (roleId) => {
        resolvedRoles.push(roleId);
        return {
          provider,
          providerConfig: { timeoutMs: 10_000, model: roleModels.get(roleId) ?? "fallback-model" },
        };
      },
    }),
  );

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 3);
  assert.deepEqual(resolvedRoles, ["injection-and-execution", ...judgeAndAggregatorIds]);
  assert.deepEqual(provider.configs.map((config) => config?.model), [
    "model-injection",
    "model-judge",
    "model-aggregator",
  ]);
  if (result.ok) {
    assert.deepEqual(result.agentMode.agentsUsed, [...highSpecialistIds, ...judgeAndAggregatorIds]);
    assert.deepEqual(result.agentMode.agents?.map((agent) => agent.id), ["injection-and-execution", ...judgeAndAggregatorIds]);
    assert.deepEqual(result.agentMode.agents?.map((agent) => agent.model), [
      "model-injection",
      "model-judge",
      "model-aggregator",
    ]);
    assert.equal(result.agentMode.candidateFindingCount, 1);
    assert.ok(result.findings[0]?.agent?.sourceFindingIds?.[0]?.startsWith("candidate-"));
  }
});

test("scanner + MoA mode judges scanner and agent candidates together", async () => {
  const repo = await fixtureRepo();
  const provider = fakeProvider((request) => {
    const content = request.messages.at(-1)?.content ?? "";
    if (content.includes("false-positive judge")) {
      assert.match(content, /scanner-backed/);
      assert.match(content, /scanner:scanner-eval/);
      return JSON.stringify({
        judgments: [
          {
            candidateId: "scanner:scanner-eval",
            verdict: "accepted",
            confidence: "high",
            reason: "Scanner evidence points at the supplied eval snippet.",
          },
        ],
      });
    }
    if (content.includes("scanner + MoA final aggregator")) {
      assert.match(content, /scanner:scanner-eval/);
      return findingResponse("hybrid-agg", ["scanner:scanner-eval"]);
    }
    return JSON.stringify({ findings: [] });
  });

  const result = await withProductAgentPanelEnv({}, () =>
    runProductAgentScan({
      repoRoot: repo,
      mode: "scanner-moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000 },
      scannerFindings: [scannerEvalFinding()],
    }),
  );

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 3);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.tool, "hermsec-scanner-moa");
    assert.equal(result.findings[0]?.agent?.mode, "scanner-moa-assisted");
    assert.equal(result.findings[0]?.agent?.source, "moa-aggregator");
    assert.deepEqual(result.findings[0]?.agent?.sourceFindingIds, ["scanner:scanner-eval"]);
    assert.equal(result.agentMode.scanMode, "scanner-moa-assisted");
    assert.equal(result.agentMode.candidateFindingCount, 1);
    assert.equal(result.agentMode.acceptedFindingCount, 1);
    assert.equal(result.agentMode.rejectedFindingCount, 0);
    assert.deepEqual(result.agentMode.agentsUsed, ["scanner-stack", ...lowSpecialistIds, ...judgeAndAggregatorIds]);
    assert.deepEqual(result.agentMode.agents?.map((agent) => agent.id), ["scanner-stack", "injection-and-execution", ...judgeAndAggregatorIds]);
  }
});

test("scanner + MoA high panel expands specialist fan-out while preserving scanner routing", async () => {
  const repo = await fixtureRepo();
  const provider = fakeProvider((request) => {
    const content = request.messages.at(-1)?.content ?? "";
    if (content.includes("false-positive judge")) {
      assert.match(content, /scanner-backed/);
      assert.match(content, /scanner:scanner-eval/);
      return acceptedJudgmentResponse(["scanner:scanner-eval"]);
    }
    if (content.includes("scanner + MoA final aggregator")) {
      assert.match(content, /scanner:scanner-eval/);
      return findingResponse("hybrid-agg", ["scanner:scanner-eval"]);
    }
    return JSON.stringify({ findings: [] });
  });

  const result = await withProductAgentPanelEnv({ HERMSEC_PRODUCT_AGENT_PANEL: "high" }, () =>
    runProductAgentScan({
      repoRoot: repo,
      mode: "scanner-moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000 },
      scannerFindings: [scannerEvalFinding()],
    }),
  );

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 3);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.agentMode.candidateFindingCount, 1);
    assert.equal(result.agentMode.acceptedFindingCount, 1);
    assert.deepEqual(result.agentMode.agentsUsed, ["scanner-stack", ...highSpecialistIds, ...judgeAndAggregatorIds]);
    assert.deepEqual(result.agentMode.agents?.map((agent) => agent.id), ["scanner-stack", "injection-and-execution", ...judgeAndAggregatorIds]);
  }
});

test("scanner + MoA retains judge-accepted findings when final aggregator fails", async () => {
  const repo = await fixtureRepo();
  const provider = fakeProvider((request) => {
    const content = request.messages.at(-1)?.content ?? "";
    if (content.includes("false-positive judge")) {
      return acceptedJudgmentResponse(["scanner:scanner-eval"]);
    }
    if (content.includes("scanner + MoA final aggregator")) {
      throw new Error("empty provider content");
    }
    return JSON.stringify({ findings: [] });
  });

  const result = await withProductAgentPanelEnv({}, () =>
    runProductAgentScan({
      repoRoot: repo,
      mode: "scanner-moa-assisted",
      provider,
      providerConfig: { timeoutMs: 10_000 },
      scannerFindings: [scannerEvalFinding()],
    }),
  );

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.agent?.source, "scanner-backed");
    assert.equal(result.agentMode.acceptedFindingCount, 1);
    assert.match(result.limitations.join(" "), /aggregator failed safely/i);
  }
});

async function fixtureRepo(): Promise<string> {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-agent-runtime-"));
  await fs.mkdir(path.join(repo, "src"), { recursive: true });
  await fs.mkdir(path.join(repo, "node_modules", "pkg"), { recursive: true });
  await fs.writeFile(path.join(repo, "src", "app.js"), "const value = eval(req.query.value);\n", "utf8");
  await fs.writeFile(path.join(repo, "node_modules", "pkg", "index.js"), "eval('ignored');\n", "utf8");
  return repo;
}

function fakeProvider(handler: (request: ModelRequest, count: number) => string): ModelProviderAdapter & {
  requests: ModelRequest[];
  configs: Array<ProviderConfig | undefined>;
} {
  const requests: ModelRequest[] = [];
  const configs: Array<ProviderConfig | undefined> = [];
  return {
    id: "openai-compatible",
    requests,
    configs,
    async listModels() {
      return [{ id: "test-model", local: true }];
    },
    async healthCheck(): Promise<ProviderHealth> {
      return { ok: true, provider: "openai-compatible", message: "ok", local: true };
    },
    async complete(request: ModelRequest, config?: ProviderConfig) {
      requests.push(request);
      configs.push(config);
      return {
        provider: "openai-compatible",
        model: config?.model ?? "test-model",
        content: handler(request, requests.length),
      };
    },
  };
}

function findingResponse(candidateId: string, sourceFindingIds: string[] = []): string {
  return JSON.stringify({
    findings: [
      {
        candidateId,
        title: "Unsafe eval on request input",
        category: "code",
        severity: "high",
        confidence: "high",
        description: "Request-controlled input reaches eval.",
        evidence: "src/app.js line 1 calls eval(req.query.value).",
        remediation: "Remove eval and use a safe parser or explicit allowlist.",
        ruleId: "hermsec.agent.unsafe-eval",
        cwe: ["CWE-95"],
        location: { file: "src/app.js", startLine: 1, endLine: 1 },
        sourceFindingIds,
      },
    ],
  });
}

function fakeMoaProvider(): ReturnType<typeof fakeProvider> {
  return fakeProvider((request, count) => {
    const content = request.messages.at(-1)?.content ?? "";
    const ids = promptCandidateIds(content);
    if (content.includes("false-positive judge")) {
      return acceptedJudgmentResponse(ids);
    }
    if (content.includes("MoA aggregator")) {
      return findingResponse("agg-candidate", ids);
    }
    return findingResponse(ids[0] ?? `candidate-missing-${count}`);
  });
}

function firstPromptCandidateId(request: ModelRequest): string | undefined {
  return promptCandidateIds(request.messages.at(-1)?.content ?? "")[0];
}

function promptCandidateIds(content: string): string[] {
  return [
    ...new Set(
      [...content.matchAll(/"candidateId"\s*:\s*"([^"]+)"/g)]
        .map((match) => match[1]!)
        .filter((value) => value.startsWith("candidate-") || value.startsWith("scanner:")),
    ),
  ];
}

function acceptedJudgmentResponse(ids: readonly string[]): string {
  return JSON.stringify({
    judgments: ids.map((candidateId) => ({
      candidateId,
      verdict: "accepted",
      confidence: "high",
      reason: "Evidence points at the supplied snippet.",
    })),
  });
}

function scannerEvalFinding(): Finding {
  return {
    id: "scanner-eval",
    title: "Unsafe eval from scanner",
    category: "code",
    severity: "high",
    confidence: "confirmed",
    description: "Scanner reported request-controlled eval.",
    evidence: "src/app.js line 1 calls eval(req.query.value).",
    remediation: "Remove eval and replace it with safe parsing.",
    tool: "semgrep",
    ruleId: "javascript.lang.security.audit.eval-detected",
    cwe: ["CWE-95"],
    location: { file: "src/app.js", startLine: 1, endLine: 1 },
    fingerprint: "fp-scanner-eval",
  };
}

async function withProductAgentPanelEnv<T>(
  values: Partial<Record<(typeof productAgentPanelEnvNames)[number], string>>,
  run: () => Promise<T>,
): Promise<T> {
  const previous = new Map(productAgentPanelEnvNames.map((name) => [name, process.env[name]]));
  try {
    for (const name of productAgentPanelEnvNames) {
      const value = values[name];
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
    return await run();
  } finally {
    for (const name of productAgentPanelEnvNames) {
      const value = previous.get(name);
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}
