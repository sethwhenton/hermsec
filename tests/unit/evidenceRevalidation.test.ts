import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCodeInspectionRuntime } from "../../src/agent/codeInspection.js";
import { revalidateProductFindingEvidence, type EvidenceSourceCandidate } from "../../src/agent/evidenceRevalidation.js";
import type { Finding } from "../../src/shared/types.js";

test("evidence revalidation rejects a finding for a file outside the repo source set", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  const result = await revalidateProductFindingEvidence({
    finding: agentFinding({
      location: { file: "src/missing.js", startLine: 1, endLine: 1 },
    }),
    runtime,
  });

  assert.equal(result.ok, false);
  assert.match(result.reasons.join("\n"), /file evidence is not readable/i);
});

test("evidence revalidation rejects impossible line references", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  const result = await revalidateProductFindingEvidence({
    finding: agentFinding({
      evidence: "src/app.js line 10 calls eval(req.query.value).",
      location: { file: "src/app.js", startLine: 10, endLine: 10 },
    }),
    runtime,
  });

  assert.equal(result.ok, false);
  assert.match(result.reasons.join("\n"), /line 10 does not exist/i);
});

test("evidence revalidation rejects API claims that are not near the cited snippet", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  const result = await revalidateProductFindingEvidence({
    finding: agentFinding({
      title: "Shell spawn on request input",
      description: "Request-controlled input reaches spawn.",
      evidence: "src/app.js line 1 calls spawn(req.query.value).",
      ruleId: "hermsec.agent.spawn",
      cwe: ["CWE-78"],
    }),
    runtime,
  });

  assert.equal(result.ok, false);
  assert.match(result.reasons.join("\n"), /source\/sink\/API text is not near evidence: spawn|unsupported CWE claim: CWE-78/i);
});

test("evidence revalidation rejects unknown aggregator source candidate IDs", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  const result = await revalidateProductFindingEvidence({
    finding: aggregatorFinding({
      agent: {
        ...aggregatorAgent(["scanner:invented"]),
        candidateIds: ["agg-candidate"],
      },
    }),
    runtime,
    sourceCandidates: [scannerSourceCandidate()],
    requireKnownSourceIds: true,
  });

  assert.equal(result.ok, false);
  assert.match(result.reasons.join("\n"), /unknown source candidate ID: scanner:invented/i);
});

test("evidence revalidation rejects aggregator-invented scanner, CVE, and CWE evidence", async () => {
  const repo = await fixtureRepo();
  const runtime = await createCodeInspectionRuntime(repo);

  const result = await revalidateProductFindingEvidence({
    finding: aggregatorFinding({
      title: "Unsafe eval confirmed by snyk",
      description: "Aggregator says Snyk confirmed an unrelated injection advisory.",
      evidence: "src/app.js line 1 calls eval(req.query.value), confirmed by snyk as CVE-2024-9999 with CWE-89.",
      cwe: ["CWE-89"],
      agent: aggregatorAgent(["scanner:scanner-eval"]),
    }),
    runtime,
    sourceCandidates: [scannerSourceCandidate()],
    requireKnownSourceIds: true,
  });

  assert.equal(result.ok, false);
  const reasons = result.reasons.join("\n");
  assert.match(reasons, /unknown scanner ID claim: snyk/i);
  assert.match(reasons, /unsupported CVE claim: CVE-2024-9999/i);
  assert.match(reasons, /unsupported CWE claim: CWE-89/i);
});

async function fixtureRepo(): Promise<string> {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-evidence-revalidation-"));
  await fs.mkdir(path.join(repo, "src"), { recursive: true });
  await fs.writeFile(
    path.join(repo, "src", "app.js"),
    [
      "const value = eval(req.query.value);",
      "const safe = String(req.query.value);",
    ].join("\n"),
    "utf8",
  );
  return repo;
}

function agentFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-agent-eval",
    title: "Unsafe eval on request input",
    category: "code",
    severity: "high",
    confidence: "high",
    description: "Request-controlled input reaches eval.",
    evidence: "src/app.js line 1 calls eval(req.query.value).",
    remediation: "Remove eval and use a safe parser or allowlist.",
    tool: "hermsec-agent",
    ruleId: "hermsec.agent.unsafe-eval",
    cwe: ["CWE-95"],
    location: { file: "src/app.js", startLine: 1, endLine: 1 },
    agent: {
      mode: "single-agent",
      source: "single-agent",
      provider: "test-provider",
      generatedAt: "2026-01-01T00:00:00.000Z",
      candidateIds: ["agent:candidate"],
    },
    fingerprint: "fp-agent-eval",
    ...overrides,
  };
}

function aggregatorFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ...agentFinding({
      id: "finding-aggregated-eval",
      tool: "hermsec-scanner-moa",
      agent: aggregatorAgent(["scanner:scanner-eval"]),
      fingerprint: "fp-aggregated-eval",
    }),
    ...overrides,
  };
}

function aggregatorAgent(sourceFindingIds: string[]): NonNullable<Finding["agent"]> {
  return {
    mode: "scanner-moa-assisted",
    source: "moa-aggregator",
    provider: "test-provider",
    generatedAt: "2026-01-01T00:00:00.000Z",
    candidateIds: ["agg-candidate"],
    sourceFindingIds,
    judge: {
      verdict: "accepted",
      reviewedBy: "moa-false-positive-judge",
    },
  };
}

function scannerSourceCandidate(): EvidenceSourceCandidate {
  return {
    candidateId: "scanner:scanner-eval",
    finding: {
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
      agent: {
        mode: "scanner-moa-assisted",
        source: "scanner-backed",
        provider: "hermsec-scanners",
        role: "semgrep",
        generatedAt: "2026-01-01T00:00:00.000Z",
        candidateIds: ["scanner:scanner-eval"],
        sourceFindingIds: ["scanner-eval"],
      },
      fingerprint: "fp-scanner-eval",
    },
  };
}
