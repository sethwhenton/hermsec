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

test("assist mode normalization accepts scanner-model-summary as deep-assisted alias", () => {
  assert.equal(assistModeFrom("scanner-model-summary"), "deep-assisted");
  assert.equal(assistModeFrom(undefined), "deep-assisted");
  assert.equal(assistModeFrom("single-agent"), "single-agent");
  assert.equal(assistModeFrom("moa-assisted"), "moa-assisted");
  assert.equal(assistModeFrom("scanner-moa-assisted"), "scanner-moa-assisted");
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
  const provider = fakeProvider(() => findingResponse("single-candidate"));
  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "single-agent",
    provider,
    providerConfig: { timeoutMs: 10_000 },
  });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.tool, "hermsec-agent");
    assert.equal(result.findings[0]?.location?.file, "src/app.js");
    assert.equal(result.findings[0]?.agent?.source, "single-agent");
    assert.equal(result.findings[0]?.agent?.provider, "openai-compatible");
    assert.doesNotMatch(provider.requests[0]?.messages.at(-1)?.content ?? "", /scannerFindings|scanner-confirmed|scanner results/i);
  }
});

test("moa-assisted mode runs specialists, judge, and aggregator", async () => {
  const repo = await fixtureRepo();
  const provider = fakeProvider((request, count) => {
    const content = request.messages.at(-1)?.content ?? "";
    if (content.includes("false-positive judge")) {
      return JSON.stringify({
        judgments: [1, 2, 3].map((index) => ({
          candidateId: `cand-${index}`,
          verdict: "accepted",
          confidence: "high",
          reason: "Evidence points at the supplied snippet.",
        })),
      });
    }
    if (content.includes("MoA aggregator")) {
      return findingResponse("agg-candidate", ["cand-1", "cand-2", "cand-3"]);
    }
    return findingResponse(`cand-${count}`);
  });

  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "moa-assisted",
    provider,
    providerConfig: { timeoutMs: 10_000 },
  });

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 5);
  if (result.ok) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.tool, "hermsec-moa");
    assert.equal(result.findings[0]?.agent?.source, "moa-aggregator");
    assert.equal(result.findings[0]?.agent?.judge?.reviewedBy, "moa-false-positive-judge");
    assert.deepEqual(result.findings[0]?.agent?.sourceFindingIds, ["cand-1", "cand-2", "cand-3"]);
    for (const request of provider.requests) {
      assert.doesNotMatch(request.messages.at(-1)?.content ?? "", /scannerFindings|scanner-confirmed|scanner results/i);
    }
  }
});

test("moa-assisted mode honors per-role model selections", async () => {
  const repo = await fixtureRepo();
  const provider = fakeProvider((request, count) => {
    const content = request.messages.at(-1)?.content ?? "";
    if (content.includes("false-positive judge")) {
      return JSON.stringify({
        judgments: [1, 2, 3].map((index) => ({
          candidateId: `cand-${index}`,
          verdict: "accepted",
          confidence: "high",
          reason: "Evidence points at the supplied snippet.",
        })),
      });
    }
    if (content.includes("MoA aggregator")) {
      return findingResponse("agg-candidate", ["cand-1", "cand-2", "cand-3"]);
    }
    return findingResponse(`cand-${count}`);
  });
  const roleModels = new Map([
    ["injection-and-execution", "model-injection"],
    ["auth-and-data-flow", "model-auth"],
    ["secrets-and-config", "model-secrets"],
    ["moa-false-positive-judge", "model-judge"],
    ["moa-aggregator", "model-aggregator"],
  ]);

  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "moa-assisted",
    provider,
    providerConfig: { timeoutMs: 10_000, model: "fallback-model" },
    modelResolver: async (roleId) => ({
      provider,
      providerConfig: { timeoutMs: 10_000, model: roleModels.get(roleId) ?? "fallback-model" },
    }),
  });

  assert.equal(result.ok, true);
  assert.deepEqual(provider.configs.map((config) => config?.model), [
    "model-injection",
    "model-auth",
    "model-secrets",
    "model-judge",
    "model-aggregator",
  ]);
  if (result.ok) {
    assert.ok(result.agentMode.agents);
    const models = result.agentMode.agents.map((agent) => agent.model);
    assert.deepEqual(models, [
      "model-injection",
      "model-auth",
      "model-secrets",
      "model-judge",
      "model-aggregator",
    ]);
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

  const result = await runProductAgentScan({
    repoRoot: repo,
    mode: "scanner-moa-assisted",
    provider,
    providerConfig: { timeoutMs: 10_000 },
    scannerFindings: [
      {
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
      },
    ],
  });

  assert.equal(result.ok, true);
  assert.equal(provider.requests.length, 5);
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
