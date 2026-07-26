import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runCanonicalAgentDetector } from "../../src/agent/canonicalHarness.js";
import type {
  ModelProviderAdapter,
  ModelRequest,
  ModelResponse,
  ProviderConfig,
  ProviderHealth,
} from "../../src/model/provider.js";

test("MoA High isolates all five specialists, caps concurrency, normalizes malformed judgments, preserves aggregator omissions, and runs one gap-fill pass", async () => {
  const repo = await createMoaFixture();
  const provider = mochaProvider({ malformedJudge: true, omitGroups: true });
  const resolved: Array<{ role: string; gapFill: boolean }> = [];

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-high",
      runId: "integration-moa-high",
      resolveModel: ({ role, gapFill }) => {
        resolved.push({ role, gapFill });
        return { provider, providerConfig: { model: `metered-${role}` } };
      },
    });

    const initialRoles = result.roles.filter((role) => !role.gapFill);
    assert.equal(initialRoles.length, 5);
    assert.deepEqual(
      initialRoles.map((role) => role.role),
      [
        "injection-and-execution",
        "identity-and-request-security",
        "sensitive-data-and-cryptography",
        "dependencies-and-supply-chain",
        "platform-storage-and-deployment",
      ],
    );
    assert.ok(provider.maxInspectionConcurrency <= 2);
    assert.equal(result.coverage.kind, "moa");
    if (result.coverage.kind === "moa") {
      assert.equal(result.coverage.gapFillExecuted, true);
    }
    assert.equal(resolved.filter((entry) => entry.gapFill).length, 1);
    assert.equal(resolved.some((entry) => entry.role === "moa-judge"), true);
    assert.equal(resolved.some((entry) => entry.role === "moa-aggregator"), true);
    assert.equal(result.judgments?.every((judgment) => judgment.verdict === "needs-review"), true);
    assert.equal(result.groups?.every((group) => group.source === "preserved"), true);
    assert.equal(result.findings.length, 1);
    assert.match(result.limitations.join(" "), /malformed decisions/u);
    assert.match(result.limitations.join(" "), /omitted known eligible/u);
    assert.equal(Object.isFrozen(result.judgments ?? []), true);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("MoA safely retains accepted candidates when the aggregator provider fails", async () => {
  const repo = await createMoaFixture();
  const provider = mochaProvider({ failAggregator: true });

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-low",
      resolveModel: () => ({ provider }),
    });

    assert.equal(result.status, "degraded");
    assert.ok((result.judgments?.length ?? 0) > 0);
    assert.equal(result.judgments?.every((judgment) => judgment.verdict === "accepted"), true);
    assert.equal(result.findings.length, 1);
    assert.equal(result.groups?.every((group) => group.source === "preserved"), true);
    assert.match(result.limitations.join(" "), /aggregator provider failed/u);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("MoA structured roles require abort support before dispatch", async () => {
  const repo = await createMoaFixture();
  const provider = mochaProvider({});
  const unabortableJudge: ModelProviderAdapter = {
    ...provider,
    capabilities: {
      tools: true,
      jsonResponse: true,
      externalAbort: false,
      streaming: false,
    },
  };

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-low",
      resolveModel: ({ role }) => ({
        provider:
          role === "moa-judge"
            ? unabortableJudge
            : provider,
      }),
    });

    assert.equal(result.status, "degraded");
    assert.equal(provider.judgeRequests, 0);
    assert.match(
      result.limitations.join(" "),
      /provider-capability-limit/u,
    );
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("MoA judge and aggregator share a hard aggregate token budget", async () => {
  const repo = await createMoaFixture();
  const provider = mochaProvider({ judgeUsageTokens: 300_000 });

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-low",
      resolveModel: () => ({ provider }),
    });

    assert.equal(result.status, "degraded");
    assert.equal(provider.judgeRequests, 1);
    assert.equal(provider.aggregatorRequests, 0);
    assert.match(
      result.limitations.join(" "),
      /total-token-limit/u,
    );
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("MoA retains a conservative reservation when judge usage is missing", async () => {
  const repo = await createMoaFixture();
  const provider = mochaProvider({ omitJudgeUsage: true });

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-low",
      resolveModel: () => ({ provider }),
    });

    assert.equal(result.status, "degraded");
    assert.equal(provider.judgeRequests, 1);
    assert.equal(provider.aggregatorRequests, 0);
    assert.match(result.limitations.join(" "), /usage-missing/u);
    assert.match(
      result.limitations.join(" "),
      /prior-usage-unresolved/u,
    );
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("cancellation during the MoA judge stops aggregation without reporting a provider outage", async () => {
  const repo = await createMoaFixture();
  const controller = new AbortController();
  const provider = mochaProvider({ abortController: controller, abortDuring: "judge" });

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-low",
      signal: controller.signal,
      resolveModel: () => ({ provider }),
    });

    assert.equal(result.status, "canceled");
    assert.equal(provider.judgeRequests, 1);
    assert.equal(provider.aggregatorRequests, 0);
    assert.equal(result.judgments, undefined);
    assert.equal(result.groups, undefined);
    assert.doesNotMatch(result.limitations.join(" "), /provider failed|malformed decisions|omitted known eligible/u);
    assert.match(result.limitations.join(" "), /canceled before MoA adjudication/u);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test("cancellation during the MoA aggregator preserves canceled semantics without reconciliation limitations", async () => {
  const repo = await createMoaFixture();
  const controller = new AbortController();
  const provider = mochaProvider({ abortController: controller, abortDuring: "aggregator" });

  try {
    const result = await runCanonicalAgentDetector({
      repoRoot: repo,
      mode: "moa-high",
      signal: controller.signal,
      resolveModel: () => ({ provider }),
    });

    assert.equal(result.status, "canceled");
    assert.equal(provider.judgeRequests, 1);
    assert.equal(provider.aggregatorRequests, 1);
    assert.ok((result.judgments?.length ?? 0) > 0);
    assert.equal(result.judgments?.every((judgment) => judgment.verdict === "accepted"), true);
    assert.equal(result.groups, undefined);
    assert.doesNotMatch(result.limitations.join(" "), /provider failed|omitted known eligible|malformed candidate groups/u);
    assert.match(result.limitations.join(" "), /canceled before MoA adjudication/u);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

async function createMoaFixture(): Promise<string> {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-canonical-moa-"));
  await fs.mkdir(path.join(repo, "src"), { recursive: true });
  await fs.writeFile(
    path.join(repo, "src", "app.js"),
    "export function render(req) { return eval(req.query.value); }\n",
    "utf8",
  );
  await fs.writeFile(
    path.join(repo, "package.json"),
    JSON.stringify({
      name: "canonical-moa-fixture",
      version: "1.0.0",
      dependencies: { express: "5.0.0" },
    }),
    "utf8",
  );
  return repo;
}

function mochaProvider(options: {
  malformedJudge?: boolean;
  omitGroups?: boolean;
  failAggregator?: boolean;
  judgeUsageTokens?: number;
  omitJudgeUsage?: boolean;
  abortController?: AbortController;
  abortDuring?: "judge" | "aggregator";
}): ModelProviderAdapter & {
  maxInspectionConcurrency: number;
  judgeRequests: number;
  aggregatorRequests: number;
} {
  let activeInspectionRequests = 0;
  let maxInspectionConcurrency = 0;
  let judgeRequests = 0;
  let aggregatorRequests = 0;
  const provider: ModelProviderAdapter & {
    maxInspectionConcurrency: number;
    judgeRequests: number;
    aggregatorRequests: number;
  } = {
    id: "openai-compatible",
    capabilities: { tools: true, jsonResponse: true, externalAbort: true, streaming: false },
    get maxInspectionConcurrency() {
      return maxInspectionConcurrency;
    },
    get judgeRequests() {
      return judgeRequests;
    },
    get aggregatorRequests() {
      return aggregatorRequests;
    },
    async listModels() {
      return [{ id: "moa-test-model", local: true, supportsTools: true }];
    },
    async healthCheck(_config?: ProviderConfig): Promise<ProviderHealth> {
      return { ok: true, provider: "openai-compatible", message: "ready", local: true };
    },
    async complete(request: ModelRequest): Promise<ModelResponse> {
      const system = request.messages.find((message) => message.role === "system")?.content ?? "";
      if (system.includes("MoA evidence judge")) {
        judgeRequests += 1;
        if (options.abortDuring === "judge") {
          options.abortController?.abort(new Error("judge canceled"));
          return new Promise<ModelResponse>(() => undefined);
        }
        const ids = candidateIds(request);
        if (options.malformedJudge) {
          return textResponse(JSON.stringify({
            judgments: ids.slice(0, 1).map((candidateId) => ({ candidateId, verdict: "rejected" })),
          }));
        }
        const response = textResponse(JSON.stringify({
          judgments: ids.map((candidateId) => ({
            candidateId,
            verdict: "accepted",
            confidence: "high",
            reason: "The cited local snippet supports the finding.",
          })),
        }));
        if (options.judgeUsageTokens !== undefined) {
          response.usage = {
            provider: "openai-compatible",
            model: "moa-test-model",
            promptTokens: options.judgeUsageTokens,
            completionTokens: 0,
            totalTokens: options.judgeUsageTokens,
            local: true,
          };
        }
        if (options.omitJudgeUsage) {
          delete response.usage;
        }
        return response;
      }
      if (system.includes("MoA aggregator")) {
        aggregatorRequests += 1;
        if (options.abortDuring === "aggregator") {
          options.abortController?.abort(new Error("aggregator canceled"));
          return new Promise<ModelResponse>(() => undefined);
        }
        if (options.failAggregator) {
          throw new Error("mock aggregator failure");
        }
        return textResponse(JSON.stringify({ groups: options.omitGroups ? [] : candidateIds(request).map((candidateId) => ({ candidateIds: [candidateId], rationale: "Known candidate." })) }));
      }

      activeInspectionRequests += 1;
      maxInspectionConcurrency = Math.max(maxInspectionConcurrency, activeInspectionRequests);
      try {
        await delay(12);
        const hasToolEvidence = request.messages.some((message) => message.role === "tool");
        if (!hasToolEvidence) {
          return toolResponse("read-app", "read_file_snippet", {
            path: "src/app.js",
            startLine: 1,
            endLine: 1,
          });
        }
        return candidateResponse(evidenceIdFromRequest(request));
      } finally {
        activeInspectionRequests -= 1;
      }
    },
  };
  return provider;
}

function candidateResponse(evidenceId: string): ModelResponse {
  return textResponse(JSON.stringify({
    findings: [{
      candidateId: "shared-eval-candidate",
      title: "Request input reaches eval",
      category: "code",
      severity: "high",
      confidence: "high",
      description: "The route evaluates request-controlled data.",
      evidence: "The cited snippet invokes eval(req.query.value).",
      remediation: "Replace eval with explicit validation and parsing.",
      cwe: ["CWE-95"],
      evidenceIds: [evidenceId],
      sourceLocations: [{ file: "src/app.js", startLine: 1, endLine: 1 }],
    }],
    abstained: false,
  }));
}

function toolResponse(id: string, name: string, args: Record<string, unknown>): ModelResponse {
  return {
    content: "",
    model: "moa-test-model",
    provider: "openai-compatible",
    finishReason: "tool_calls",
    toolCalls: [{ id, type: "function", function: { name, arguments: JSON.stringify(args) } }],
    usage: usage(),
  };
}

function textResponse(content: string): ModelResponse {
  return {
    content,
    model: "moa-test-model",
    provider: "openai-compatible",
    finishReason: "stop",
    usage: usage(),
  };
}

function usage() {
  return {
    provider: "openai-compatible",
    model: "moa-test-model",
    promptTokens: 10,
    completionTokens: 5,
    totalTokens: 15,
    local: true,
  };
}

function candidateIds(request: ModelRequest): string[] {
  const content = request.messages.filter((message) => message.role === "user").at(-1)?.content ?? "";
  return [...new Set(
    [...content.matchAll(/"candidateId":"(candidate-[a-f0-9]{16})"/gu)]
      .map((match) => match[1]!)
      .sort(),
  )];
}

function evidenceIdFromRequest(request: ModelRequest): string {
  const content = request.messages.filter((message) => message.role === "tool").at(-1)?.content ?? "";
  const match = content.match(/evidence-[a-f0-9]{20}/u);
  assert.ok(match?.[0]);
  return match[0];
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
