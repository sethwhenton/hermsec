import assert from "node:assert/strict";
import test from "node:test";
import {
  addFindingCoverageDisclosure,
  buildConversationalFallback,
  historyBeforeCurrentQuestion,
  inferDetectorFindingCounts,
  isNearDuplicateConversationAnswer,
  validateConversationModelAnswer,
} from "../src/main/reportConversation.ts";
import { redactSecretText } from "../src/main/privacy.ts";

const evidence = {
  targetName: "demo-project",
  counts: {
    total: 3,
    critical: 0,
    high: 2,
    medium: 1,
    low: 0,
    info: 0,
    secrets: 1,
    scannerFailures: 0,
  },
  scan: {
    mode: "scanner-single",
    terminalStatus: "partial",
    degradationReasons: ["provider-request-failed"],
    generatedWithModel: false,
    modelFallbackReason:
      "No model request completed; available detector evidence was preserved.",
  },
  detectorSummary: {
    scannerFindingCount: 3,
    agentFindingCount: 0,
    finalFindingCount: 3,
    provenance: "recorded" as const,
    scanners: [
      {
        name: "Semgrep",
        status: "completed",
        findings: 2,
      },
      {
        name: "Gitleaks",
        status: "completed",
        findings: 1,
      },
    ],
    agents: [
      {
        id: "single-agent-inspector",
        label: "Single agent inspector",
        role: "single-agent-inspector",
        status: "failed",
      },
    ],
  },
  findingCoverage: {
    included: 3,
    total: 3,
    truncated: false,
  },
  findings: [
    {
      id: "finding-secret",
      title: "Exposed fixture token",
      severity: "HIGH",
      category: "secret",
      tool: "gitleaks",
      location: "app.py:9",
      description: "A token is present in source control.",
      remediation: "Move the token to a secret manager.",
    },
    {
      id: "finding-sqli",
      title: "SQL injection",
      severity: "HIGH",
      category: "sqli",
      tool: "semgrep",
      location: "app.py:24",
      description: "Request input reaches a SQL query.",
      remediation: "Use a parameterized query.",
    },
    {
      id: "finding-header",
      title: "Missing security header",
      severity: "MEDIUM",
      category: "headers",
      tool: "semgrep",
      location: "app.py:40",
      description: "The response omits a defensive header.",
      remediation: "Set the header centrally.",
    },
  ],
};

test("a follow-up asking for other findings does not repeat the canned first-finding answer", () => {
  const first = buildConversationalFallback(
    "Tell me about your findings. What did the agent and scanners find?",
    evidence,
  );
  const followUp = buildConversationalFallback(
    "What other findings exist?",
    evidence,
    [
      {
        role: "assistant",
        content: "The top issue is Exposed fixture token at app.py:9.",
      },
    ],
  );

  assert.notEqual(followUp, first);
  assert.match(followUp, /SQL injection/u);
  assert.match(followUp, /Missing security header/u);
});

test("contextual continuation shorthand advances to unseen findings", () => {
  const history = [
    {
      role: "assistant" as const,
      content: "The top issue is Exposed fixture token at app.py:9.",
    },
  ];
  for (const question of [
    "Anything else?",
    "What else?",
    "And the rest?",
    "Keep going.",
  ]) {
    const answer = buildConversationalFallback(question, evidence, history);
    assert.match(answer, /SQL injection/u);
    assert.doesNotMatch(answer, /first issue I would inspect/u);
  }
});

test("scanner and agent questions use grounded detector provenance", () => {
  const answer = buildConversationalFallback(
    "What did the agent find and what did the scanners find?",
    evidence,
  );

  assert.match(answer, /Scanners contributed 3; model agents contributed 0/u);
  assert.match(answer, /Single agent inspector: failed/u);
  assert.match(answer, /Semgrep: 2 findings/u);
  assert.match(answer, /Gitleaks: 1 findings/u);
  assert.match(answer, /provider-request-failed/u);
});

test("the current question is removed from trailing conversation history", () => {
  const question = "What other findings exist?";
  const history = historyBeforeCurrentQuestion(
    [
      { role: "user", content: "Tell me about the findings." },
      { role: "assistant", content: "The top finding is an exposed token." },
      { role: "user", content: `  ${question.toUpperCase()}  ` },
    ],
    question,
  );

  assert.deepEqual(history, [
    { role: "user", content: "Tell me about the findings." },
    { role: "assistant", content: "The top finding is an exposed token." },
  ]);
});

test("legacy findings without source labels keep detector provenance unknown", () => {
  assert.equal(
    inferDetectorFindingCounts([
      { sourceLabels: [] },
      { sourceLabel: undefined },
    ]),
    undefined,
  );

  assert.deepEqual(
    inferDetectorFindingCounts([
      { sourceLabels: ["Semgrep"] },
      { sourceLabels: ["single-agent-inspector"] },
      { sourceLabels: ["Semgrep", "aggregator"] },
    ]),
    {
      scannerFindingCount: 2,
      agentFindingCount: 2,
    },
  );
});

test("unknown legacy provenance is disclosed instead of assigning findings to scanners", () => {
  const answer = buildConversationalFallback(
    "What did scanners and agents find?",
    {
      ...evidence,
      detectorSummary: {
        ...evidence.detectorSummary,
        provenance: "unknown",
        scannerFindingCount: undefined,
        agentFindingCount: undefined,
      },
    },
  );

  assert.match(answer, /does not contain enough provenance/u);
  assert.doesNotMatch(answer, /Scanners contributed 3/u);
});

test("ordinary security prose and model identifiers survive secret redaction", () => {
  const prose =
    "Move the secret to secret storage using deepseek-v4-flash and hermsec-conversation-smoke-model.";
  assert.equal(redactSecretText(prose), prose);

  const fakeOpenAiCredential = [
    "sk",
    "exampleValue1234567890",
  ].join("-");
  const fakeGitHubCredential = [
    "ghp",
    "abcdefghijklmnopqrstuvwxyz123456",
  ].join("_");
  const credential =
    `api_key=${fakeOpenAiCredential} and token: ${fakeGitHubCredential}`;
  const redacted = redactSecretText(credential);
  assert(!redacted.includes(fakeOpenAiCredential));
  assert(!redacted.includes(fakeGitHubCredential));
  assert.match(redacted, /api_key=\[REDACTED\]/u);
  assert.match(redacted, /token: \[REDACTED\]/u);
});

test("duplicate and hallucinated model answers are rejected while grounded natural prose passes", () => {
  const previous = [
    "The highest-priority finding is Exposed fixture token at app.py:9.",
    "It is stored in source control and should be moved to environment-backed secret storage.",
    "Rotate the exposed value after removing it.",
  ].join(" ");
  const repeated = validateConversationModelAnswer({
    answer: previous,
    question: "What other findings exist?",
    evidence,
    history: [{ role: "assistant", content: previous }],
  });
  assert.equal(repeated.ok, false);
  assert.match(repeated.reason ?? "", /repeats a prior assistant response/u);

  const hallucinated = validateConversationModelAnswer({
    answer: "The SQL injection is at app.py:999.",
    question: "Where is the SQL injection?",
    evidence,
    history: [],
  });
  assert.equal(hallucinated.ok, false);
  assert.match(hallucinated.reason ?? "", /not a recorded finding location/u);

  const wrongTotal = validateConversationModelAnswer({
    answer: "The report has 99 findings.",
    question: "How many findings are there?",
    evidence,
    history: [],
  });
  assert.equal(wrongTotal.ok, false);
  assert.match(wrongTotal.reason ?? "", /report records 3/u);

  const wrongSeverity = validateConversationModelAnswer({
    answer: "The SQL injection is LOW severity at app.py:24.",
    question: "Explain the SQL injection.",
    evidence,
    history: [],
  });
  assert.equal(wrongSeverity.ok, false);
  assert.match(wrongSeverity.reason ?? "", /report records HIGH/u);

  const natural = validateConversationModelAnswer({
    answer:
      "Let me explain the remaining issue: SQL injection at app.py:24 lets request input reach a query. Use parameters.",
    question: "What other findings exist?",
    evidence,
    history: [
      {
        role: "assistant",
        content: "The first issue is Exposed fixture token at app.py:9.",
      },
    ],
  });
  assert.equal(natural.ok, true);
});

test("model answers cannot contradict recorded run, agent, or scanner statuses", () => {
  const falseAgentStatus = validateConversationModelAnswer({
    answer:
      "The agent completed successfully and all scanners completed without errors.",
    question: "What did the agent and scanners find?",
    evidence,
    history: [],
  });
  assert.equal(falseAgentStatus.ok, false);
  assert.match(falseAgentStatus.reason ?? "", /recorded agent status is failed/u);

  const falseNamedAgentStatus = validateConversationModelAnswer({
    answer: "Single agent inspector completed successfully.",
    question: "How did the agent run?",
    evidence,
    history: [],
  });
  assert.equal(falseNamedAgentStatus.ok, false);
  assert.match(
    falseNamedAgentStatus.reason ?? "",
    /recorded agent status is failed/u,
  );

  const falseRunStatus = validateConversationModelAnswer({
    answer: "The scan completed successfully.",
    question: "Did the scan finish?",
    evidence,
    history: [],
  });
  assert.equal(falseRunStatus.ok, false);
  assert.match(falseRunStatus.reason ?? "", /terminal status is partial/u);

  const falseScannerStatus = validateConversationModelAnswer({
    answer: "All scanners failed.",
    question: "Did the scanners fail?",
    evidence,
    history: [],
  });
  assert.equal(falseScannerStatus.ok, false);
  assert.match(
    falseScannerStatus.reason ?? "",
    /recorded scanner statuses are completed/u,
  );

  const falseNamedScannerStatus = validateConversationModelAnswer({
    answer: "Semgrep failed.",
    question: "How did Semgrep run?",
    evidence,
    history: [],
  });
  assert.equal(falseNamedScannerStatus.ok, false);
  assert.match(
    falseNamedScannerStatus.reason ?? "",
    /recorded scanner status is completed/u,
  );

  const grounded = validateConversationModelAnswer({
    answer:
      "The run was partial: the model agent failed, while all scanners completed without errors.",
    question: "What did the agent and scanners find?",
    evidence,
    history: [],
  });
  assert.equal(grounded.ok, true);
});

test("mixed detector statuses validate all-path claims without rejecting ambiguous singular claims", () => {
  const mixedEvidence = {
    ...evidence,
    detectorSummary: {
      ...evidence.detectorSummary,
      agents: [
        ...evidence.detectorSummary.agents,
        {
          id: "second-agent",
          label: "Second agent",
          role: "specialist",
          status: "completed",
        },
      ],
      scanners: [
        ...evidence.detectorSummary.scanners,
        {
          name: "Broken scanner",
          status: "failed",
          findings: 0,
        },
      ],
    },
  };

  const allAgentsFailed = validateConversationModelAnswer({
    answer: "All agents failed.",
    question: "How did the agents run?",
    evidence: mixedEvidence,
    history: [],
  });
  assert.equal(allAgentsFailed.ok, false);

  const allScannersPassed = validateConversationModelAnswer({
    answer: "All scanners completed without errors.",
    question: "How did the scanners run?",
    evidence: mixedEvidence,
    history: [],
  });
  assert.equal(allScannersPassed.ok, false);

  const ambiguousSingular = validateConversationModelAnswer({
    answer: "The agent completed.",
    question: "Did an agent complete?",
    evidence: mixedEvidence,
    history: [],
  });
  assert.equal(ambiguousSingular.ok, true);

  const truthfulCompound = validateConversationModelAnswer({
    answer:
      "Semgrep completed while Broken scanner failed. Single agent inspector failed; Second agent completed.",
    question: "How did each detector run?",
    evidence: mixedEvidence,
    history: [],
  });
  assert.equal(truthfulCompound.ok, true);
});

test("an explicit repeat request may return the same answer", () => {
  const previous =
    "The report records an exposed fixture token at app.py:9 and recommends moving it out of source control before rotating the value.";
  const validation = validateConversationModelAnswer({
    answer: previous,
    question: "Repeat that verbatim.",
    evidence,
    history: [{ role: "assistant", content: previous }],
  });
  assert.equal(validation.ok, true);
});

test("near-duplicate long answers are detected despite punctuation changes", () => {
  const first = [
    "The report contains an exposed fixture token at app.py:9.",
    "The value is stored in source control, which can expose it to anyone who can read repository history.",
    "Move it to environment-backed secret storage and rotate the credential after the code change.",
  ].join(" ");
  const second = [
    "The report contains an exposed fixture token at app.py:9!",
    "The value is stored in source control—which can expose it to anyone who can read repository history.",
    "Move it to environment backed secret storage, and rotate the credential after the code change.",
  ].join(" ");
  assert.equal(isNearDuplicateConversationAnswer(second, first), true);
});

test("fallback follow-ups advance through unseen findings instead of repeating a fixed page", () => {
  const manyFindings = Array.from({ length: 13 }, (_, index) => ({
    id: `finding-${index + 1}`,
    title: `Finding ${index + 1}`,
    severity: index < 2 ? "HIGH" : "MEDIUM",
    location: `src/file-${index + 1}.ts:${index + 1}`,
    description: `Description ${index + 1}`,
    remediation: `Remediation ${index + 1}`,
  }));
  const pagedEvidence = {
    ...evidence,
    counts: { ...evidence.counts, total: manyFindings.length },
    findingCoverage: {
      included: manyFindings.length,
      indexed: manyFindings.length,
      total: manyFindings.length,
      truncated: false,
      indexTruncated: false,
    },
    findingIndex: manyFindings,
    findings: manyFindings,
  };

  const firstPage = buildConversationalFallback(
    "What other findings exist?",
    pagedEvidence,
    [],
  );
  assert.match(firstPage, /Finding 1/u);
  assert.match(firstPage, /Finding 6/u);
  assert.doesNotMatch(firstPage, /Finding 7 -/u);

  const secondPage = buildConversationalFallback(
    "What other findings remain?",
    pagedEvidence,
    [{ role: "assistant", content: firstPage }],
  );
  assert.match(secondPage, /Finding 7/u);
  assert.match(secondPage, /Finding 12/u);
  assert.doesNotMatch(secondPage, /Finding 1 -/u);

  const thirdPage = buildConversationalFallback(
    "Any more findings?",
    pagedEvidence,
    [
      { role: "assistant", content: firstPage },
      { role: "assistant", content: secondPage },
    ],
  );
  assert.match(thirdPage, /Finding 13/u);
  assert.doesNotMatch(thirdPage, /Finding 7 -/u);
});

test("responses disclose when detailed evidence covers only part of a large report", () => {
  const answer = addFindingCoverageDisclosure(
    "Here are the next findings.",
    "List all remaining findings.",
    {
      ...evidence,
      findingCoverage: {
        included: 32,
        indexed: 40,
        total: 40,
        truncated: true,
        indexTruncated: false,
      },
    },
  );
  assert.match(answer, /detailed evidence is loaded for 32 of 40 findings/u);
});

test("the compact finding index keeps findings beyond the first 32 pageable", () => {
  const indexedFindings = Array.from({ length: 40 }, (_, index) => ({
    id: `indexed-${index + 1}`,
    title: `Indexed risk ${index + 1}`,
    severity: "MEDIUM",
    location: `src/indexed-${index + 1}.ts:${index + 1}`,
  }));
  const largeEvidence = {
    ...evidence,
    counts: { ...evidence.counts, total: 40 },
    findings: indexedFindings.slice(0, 32).map((finding) => ({
      ...finding,
      description: `Description for ${finding.title}`,
      remediation: `Remediation for ${finding.title}`,
    })),
    findingIndex: indexedFindings,
    findingCoverage: {
      included: 32,
      indexed: 40,
      total: 40,
      truncated: true,
      indexTruncated: false,
    },
  };
  const alreadyCovered = indexedFindings
    .slice(0, 36)
    .map((finding) => `${finding.title} at ${finding.location}`)
    .join("\n");
  const answer = buildConversationalFallback(
    "What remaining findings are there?",
    largeEvidence,
    [{ role: "assistant", content: alreadyCovered }],
  );

  assert.match(answer, /Indexed risk 37/u);
  assert.match(answer, /Indexed risk 40/u);
  assert.doesNotMatch(answer, /Indexed risk 36 -/u);
  assert.match(answer, /Detailed explanations are loaded for 32 of 40 findings/u);
});

test("fallback pagination distinguishes duplicate titles by location", () => {
  const duplicateTitleEvidence = {
    ...evidence,
    counts: { ...evidence.counts, total: 2 },
    findingIndex: [
      {
        id: "duplicate-a",
        title: "Unsafe query",
        severity: "HIGH",
        location: "src/a.ts:10",
      },
      {
        id: "duplicate-b",
        title: "Unsafe query",
        severity: "HIGH",
        location: "src/b.ts:20",
      },
    ],
    findings: [
      {
        id: "duplicate-a",
        title: "Unsafe query",
        severity: "HIGH",
        location: "src/a.ts:10",
        description: "First query.",
        remediation: "Parameterize it.",
      },
      {
        id: "duplicate-b",
        title: "Unsafe query",
        severity: "HIGH",
        location: "src/b.ts:20",
        description: "Second query.",
        remediation: "Parameterize it.",
      },
    ],
  };
  const answer = buildConversationalFallback(
    "What other findings remain?",
    duplicateTitleEvidence,
    [
      {
        role: "assistant",
        content: "Unsafe query at src/a.ts:10 is the first issue.",
      },
    ],
  );

  assert.match(answer, /src\/b\.ts:20/u);
  assert.doesNotMatch(answer, /src\/a\.ts:10/u);
});
