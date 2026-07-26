import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeMoaJudgments,
  reconcileMoaAggregation,
  type MoaJudgment,
} from "../../src/agent/moaAdjudication.js";

test("missing, malformed, conflicting, and provider-error judgments require review", () => {
  const normalized = normalizeMoaJudgments({
    candidateIds: [
      "candidate-c",
      "candidate-a",
      "candidate-e",
      "candidate-b",
      "candidate-d",
    ],
    reviewedBy: "test-judge",
    output: {
      judgments: [
        {
          candidateId: "candidate-a",
          verdict: "accepted",
          confidence: "high",
          reason: "Evidence is concrete.",
        },
        {
          candidateId: "candidate-b",
          verdict: "maybe",
        },
        {
          candidateId: "candidate-d",
          verdict: "accepted",
        },
        {
          candidateId: "candidate-d",
          verdict: "rejected",
        },
        {
          candidateId: "candidate-e",
          verdict: "accepted",
          confidence: "medium",
          reason: "First duplicate.",
        },
        {
          candidateId: "candidate-e",
          verdict: "accepted",
          confidence: "medium",
          reason: "Second duplicate.",
        },
        {
          candidateId: "candidate-unknown",
          verdict: "accepted",
        },
      ],
    },
  });

  assert.deepEqual(
    normalized.judgments.map((judgment) => [
      judgment.candidateId,
      judgment.verdict,
      judgment.source,
    ]),
    [
      ["candidate-a", "accepted", "judge"],
      ["candidate-b", "needs-review", "fallback"],
      ["candidate-c", "needs-review", "fallback"],
      ["candidate-d", "needs-review", "fallback"],
      ["candidate-e", "needs-review", "fallback"],
    ],
  );
  assert.deepEqual(normalized.unknownCandidateIds, ["candidate-unknown"]);
  assert.equal(normalized.malformedEntryCount, 2);

  const failed = normalizeMoaJudgments({
    candidateIds: ["candidate-a", "candidate-b"],
    output: {
      judgments: [
        { candidateId: "candidate-a", verdict: "rejected" },
      ],
    },
    providerError: new Error("provider timeout"),
  });

  assert.equal(failed.providerFailed, true);
  assert.deepEqual(
    failed.judgments.map((judgment) => judgment.verdict),
    ["needs-review", "needs-review"],
  );
});

test("a rejection requires an explicit valid confidence and reason", () => {
  const normalized = normalizeMoaJudgments({
    candidateIds: [
      "missing-confidence",
      "missing-reason",
      "malformed-confidence",
      "valid-rejection",
    ],
    output: {
      judgments: [
        {
          candidateId: "missing-confidence",
          verdict: "rejected",
          reason: "Evidence is unsupported.",
        },
        {
          candidateId: "missing-reason",
          verdict: "rejected",
          confidence: "high",
        },
        {
          candidateId: "malformed-confidence",
          verdict: "rejected",
          confidence: "certain",
          reason: "Evidence is unsupported.",
        },
        {
          candidateId: "valid-rejection",
          verdict: "rejected",
          confidence: "high",
          reason: "The cited path does not contain the claimed sink.",
        },
      ],
    },
  });

  assert.deepEqual(
    normalized.judgments.map((judgment) => [
      judgment.candidateId,
      judgment.verdict,
    ]),
    [
      ["malformed-confidence", "needs-review"],
      ["missing-confidence", "needs-review"],
      ["missing-reason", "needs-review"],
      ["valid-rejection", "rejected"],
    ],
  );
  assert.equal(normalized.malformedEntryCount, 3);
});

test("duplicate direct judgments reconcile deterministically to needs-review", () => {
  const candidates = [{ candidateId: "candidate-a" }];
  const accepted = judgment("candidate-a", "accepted");
  const rejected = judgment("candidate-a", "rejected");
  const first = reconcileMoaAggregation({
    candidates,
    judgments: [accepted, rejected],
    output: { groups: [] },
  });
  const second = reconcileMoaAggregation({
    candidates,
    judgments: [rejected, accepted],
    output: { groups: [] },
  });

  assert.deepEqual(second, first);
  assert.deepEqual(first.acceptedCandidateIds, []);
  assert.deepEqual(first.rejectedCandidateIds, []);
  assert.deepEqual(first.needsReviewCandidateIds, ["candidate-a"]);
  assert.deepEqual(
    first.retainedCandidates.map((candidate) => candidate.candidateId),
    ["candidate-a"],
  );
});

test("a malformed direct rejection reconciles to needs-review", () => {
  const malformed = {
    candidateId: "candidate-a",
    verdict: "rejected",
    confidence: "low",
    source: "judge",
  } as MoaJudgment;
  const result = reconcileMoaAggregation({
    candidates: [{ candidateId: "candidate-a" }],
    judgments: [malformed],
    output: { groups: [] },
  });

  assert.deepEqual(result.rejectedCandidateIds, []);
  assert.deepEqual(result.needsReviewCandidateIds, ["candidate-a"]);
});

test("partial aggregation blocks unknown IDs and preserves every eligible candidate", () => {
  const candidates = [
    { candidateId: "candidate-a", title: "A" },
    { candidateId: "candidate-b", title: "B" },
    { candidateId: "candidate-c", title: "C" },
    { candidateId: "candidate-d", title: "D" },
  ];
  const judgments: MoaJudgment[] = [
    judgment("candidate-a", "accepted"),
    judgment("candidate-b", "needs-review"),
    judgment("candidate-c", "accepted"),
    judgment("candidate-d", "rejected"),
  ];

  const result = reconcileMoaAggregation({
    candidates,
    judgments,
    output: {
      groups: [
        {
          candidateIds: ["candidate-a", "candidate-b", "candidate-invented"],
          rationale: "Same data flow.",
        },
      ],
    },
  });

  assert.equal(result.status, "partial");
  assert.deepEqual(
    result.retainedCandidates.map((candidate) => candidate.candidateId),
    ["candidate-a", "candidate-b", "candidate-c"],
  );
  assert.deepEqual(result.rejectedCandidateIds, ["candidate-d"]);
  assert.deepEqual(result.needsReviewCandidateIds, ["candidate-b"]);
  assert.deepEqual(result.unknownCandidateIds, ["candidate-invented"]);
  assert.deepEqual(result.unmentionedCandidateIds, ["candidate-c"]);
  assert.deepEqual(
    result.groups.map((group) => group.candidateIds),
    [["candidate-a", "candidate-b"], ["candidate-c"]],
  );
  assert.deepEqual(
    result.groups.map((group) => group.source),
    ["aggregator", "preserved"],
  );
});

test("aggregation reconciliation is deterministic across candidate and group order", () => {
  const candidates = [
    { candidateId: "candidate-a", value: 1 },
    { candidateId: "candidate-b", value: 2 },
    { candidateId: "candidate-c", value: 3 },
  ];
  const judgments = [
    judgment("candidate-a", "accepted"),
    judgment("candidate-b", "accepted"),
    judgment("candidate-c", "needs-review"),
  ];
  const groups = [
    {
      candidateIds: ["candidate-b", "candidate-c"],
      rationale: "Shared sink.",
    },
    {
      candidateIds: ["candidate-a", "candidate-b"],
      rationale: "Shared source.",
    },
  ];

  const first = reconcileMoaAggregation({
    candidates,
    judgments,
    output: { groups },
  });
  const second = reconcileMoaAggregation({
    candidates: [...candidates].reverse(),
    judgments: [...judgments].reverse(),
    output: {
      groups: [...groups]
        .reverse()
        .map((group) => ({
          ...group,
          candidateIds: [...group.candidateIds].reverse(),
        })),
    },
  });

  assert.deepEqual(second, first);
  assert.equal(first.groups.length, 1);
  assert.deepEqual(
    first.groups[0]?.candidateIds,
    ["candidate-a", "candidate-b", "candidate-c"],
  );
});

test("aggregator provider failure preserves accepted and review candidates", () => {
  const result = reconcileMoaAggregation({
    candidates: [
      { candidateId: "candidate-a" },
      { candidateId: "candidate-b" },
      { candidateId: "candidate-c" },
    ],
    judgments: [
      judgment("candidate-a", "accepted"),
      judgment("candidate-b", "needs-review"),
      judgment("candidate-c", "rejected"),
    ],
    output: {
      groups: [{ candidateIds: ["candidate-c"] }],
    },
    providerError: new Error("aggregator timeout"),
  });

  assert.equal(result.status, "degraded");
  assert.equal(result.providerFailed, true);
  assert.deepEqual(
    result.retainedCandidates.map((candidate) => candidate.candidateId),
    ["candidate-a", "candidate-b"],
  );
  assert.deepEqual(
    result.groups.map((group) => group.candidateIds),
    [["candidate-a"], ["candidate-b"]],
  );
});

function judgment(
  candidateId: string,
  verdict: MoaJudgment["verdict"],
): MoaJudgment {
  return {
    candidateId,
    verdict,
    confidence: verdict === "accepted" ? "high" : "low",
    reason: `Test ${verdict} judgment.`,
    reviewedBy: "test-judge",
    source: "judge",
  };
}
