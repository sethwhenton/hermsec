import { stableId } from "../shared/text.js";

export type MoaJudgmentVerdict = "accepted" | "rejected" | "needs-review";
export type MoaJudgmentConfidence = "low" | "medium" | "high";

export type MoaJudgment = {
  candidateId: string;
  verdict: MoaJudgmentVerdict;
  confidence: MoaJudgmentConfidence;
  reason: string;
  reviewedBy?: string;
  source: "judge" | "fallback";
};

export type MoaJudgmentNormalization = {
  judgments: MoaJudgment[];
  unknownCandidateIds: string[];
  malformedEntryCount: number;
  providerFailed: boolean;
};

export type MoaCandidateLike = {
  candidateId: string;
};

export type MoaAggregationGroup = {
  groupId: string;
  candidateIds: string[];
  rationales: string[];
  source: "aggregator" | "preserved";
};

export type MoaAggregationReconciliation<T extends MoaCandidateLike> = {
  status: "completed" | "partial" | "degraded";
  groups: MoaAggregationGroup[];
  retainedCandidates: T[];
  acceptedCandidateIds: string[];
  needsReviewCandidateIds: string[];
  rejectedCandidateIds: string[];
  unmentionedCandidateIds: string[];
  unknownCandidateIds: string[];
  malformedGroupCount: number;
  providerFailed: boolean;
};

export function normalizeMoaJudgments(input: {
  candidateIds: readonly string[];
  output?: unknown;
  providerError?: unknown;
  reviewedBy?: string;
}): MoaJudgmentNormalization {
  const candidateIds = uniqueCandidateIds(input.candidateIds);
  const known = new Set(candidateIds);
  if (input.providerError !== undefined) {
    return {
      judgments: candidateIds.map((candidateId) => fallbackJudgment(
        candidateId,
        "Judge provider failed; candidate requires review.",
        input.reviewedBy,
      )),
      unknownCandidateIds: [],
      malformedEntryCount: 0,
      providerFailed: true,
    };
  }

  const rawEntries = rawJudgmentEntries(input.output);
  const byCandidate = new Map<string, MoaJudgment[]>();
  const unknown = new Set<string>();
  let malformedEntryCount = 0;

  for (const raw of rawEntries) {
    if (!isRecord(raw)) {
      malformedEntryCount += 1;
      continue;
    }
    const candidateId = normalizedString(raw.candidateId, 160);
    if (!candidateId) {
      malformedEntryCount += 1;
      continue;
    }
    if (!known.has(candidateId)) {
      unknown.add(candidateId);
      continue;
    }
    const verdict = judgmentVerdict(raw.verdict);
    if (!verdict) {
      malformedEntryCount += 1;
      const entries = byCandidate.get(candidateId) ?? [];
      entries.push(fallbackJudgment(
        candidateId,
        "Judge returned a malformed verdict; candidate requires review.",
        input.reviewedBy,
      ));
      byCandidate.set(candidateId, entries);
      continue;
    }
    const confidence = judgmentConfidence(raw.confidence);
    const reason = normalizedString(raw.reason, 400);
    if (verdict === "rejected" && (!confidence || !reason)) {
      malformedEntryCount += 1;
      const entries = byCandidate.get(candidateId) ?? [];
      entries.push(fallbackJudgment(
        candidateId,
        "Judge rejection omitted a valid confidence or reason; candidate requires review.",
        input.reviewedBy,
      ));
      byCandidate.set(candidateId, entries);
      continue;
    }
    const entries = byCandidate.get(candidateId) ?? [];
    entries.push({
      candidateId,
      verdict,
      confidence: confidence ?? "low",
      reason: reason ?? defaultJudgmentReason(verdict),
      ...(input.reviewedBy ? { reviewedBy: input.reviewedBy } : {}),
      source: "judge",
    });
    byCandidate.set(candidateId, entries);
  }

  const judgments = candidateIds.map((candidateId) => {
    const entries = byCandidate.get(candidateId) ?? [];
    if (entries.length === 0) {
      return fallbackJudgment(
        candidateId,
        "Judge returned no decision; candidate requires review.",
        input.reviewedBy,
      );
    }
    if (entries.length > 1) {
      return fallbackJudgment(
        candidateId,
        "Judge returned duplicate or conflicting decisions; candidate requires review.",
        input.reviewedBy,
      );
    }
    return entries[0]!;
  });

  return {
    judgments,
    unknownCandidateIds: [...unknown].sort(),
    malformedEntryCount,
    providerFailed: false,
  };
}

export function reconcileMoaAggregation<T extends MoaCandidateLike>(input: {
  candidates: readonly T[];
  judgments: readonly MoaJudgment[];
  output?: unknown;
  providerError?: unknown;
}): MoaAggregationReconciliation<T> {
  const candidates = canonicalCandidates(input.candidates);
  const candidateById = new Map(candidates.map((candidate) => [candidate.candidateId, candidate]));
  const normalizedJudgments = completeJudgments(
    candidates.map((candidate) => candidate.candidateId),
    input.judgments,
  );
  const eligible = normalizedJudgments
    .filter((judgment) => judgment.verdict !== "rejected")
    .map((judgment) => judgment.candidateId);
  const eligibleSet = new Set(eligible);
  const rejectedCandidateIds = normalizedJudgments
    .filter((judgment) => judgment.verdict === "rejected")
    .map((judgment) => judgment.candidateId);
  const acceptedCandidateIds = normalizedJudgments
    .filter((judgment) => judgment.verdict === "accepted")
    .map((judgment) => judgment.candidateId);
  const needsReviewCandidateIds = normalizedJudgments
    .filter((judgment) => judgment.verdict === "needs-review")
    .map((judgment) => judgment.candidateId);

  const unknown = new Set<string>();
  const mentioned = new Set<string>();
  const proposedGroups: Array<{ candidateIds: string[]; rationale?: string }> = [];
  let malformedGroupCount = 0;

  if (input.providerError === undefined) {
    for (const raw of rawAggregationGroups(input.output)) {
      if (!isRecord(raw) || !Array.isArray(raw.candidateIds)) {
        malformedGroupCount += 1;
        continue;
      }
      const rawIds = raw.candidateIds
        .flatMap((value) => {
          const normalized = normalizedString(value, 160);
          return normalized ? [normalized] : [];
        });
      if (rawIds.length === 0) {
        malformedGroupCount += 1;
        continue;
      }
      const knownEligible: string[] = [];
      for (const candidateId of rawIds) {
        if (!candidateById.has(candidateId) || !eligibleSet.has(candidateId)) {
          unknown.add(candidateId);
          continue;
        }
        knownEligible.push(candidateId);
        mentioned.add(candidateId);
      }
      const candidateIds = [...new Set(knownEligible)].sort();
      if (candidateIds.length === 0) {
        continue;
      }
      proposedGroups.push({
        candidateIds,
        ...(normalizedString(raw.rationale, 500)
          ? { rationale: normalizedString(raw.rationale, 500)! }
          : {}),
      });
    }
  }

  const components = connectedComponents(eligible, proposedGroups);
  const unmentionedCandidateIds = eligible.filter((candidateId) => !mentioned.has(candidateId));
  const groups = components.map((candidateIds) => {
    const touching = proposedGroups.filter((group) =>
      group.candidateIds.some((candidateId) => candidateIds.includes(candidateId))
    );
    return {
      groupId: stableId(candidateIds.join("|"), "moa-group"),
      candidateIds,
      rationales: [...new Set(touching.flatMap((group) => group.rationale ? [group.rationale] : []))].sort(),
      source: touching.length > 0 ? "aggregator" as const : "preserved" as const,
    };
  });
  const providerFailed = input.providerError !== undefined;
  const status = providerFailed
    ? "degraded" as const
    : malformedGroupCount > 0
      || unknown.size > 0
      || unmentionedCandidateIds.length > 0
      ? "partial" as const
      : "completed" as const;

  return {
    status,
    groups,
    retainedCandidates: eligible.map((candidateId) => candidateById.get(candidateId)!),
    acceptedCandidateIds,
    needsReviewCandidateIds,
    rejectedCandidateIds,
    unmentionedCandidateIds,
    unknownCandidateIds: [...unknown].sort(),
    malformedGroupCount,
    providerFailed,
  };
}

function completeJudgments(
  candidateIds: readonly string[],
  judgments: readonly MoaJudgment[],
): MoaJudgment[] {
  const known = new Set(candidateIds);
  const byId = new Map<string, MoaJudgment[]>();
  for (const judgment of judgments) {
    if (!known.has(judgment.candidateId)) {
      continue;
    }
    const entries = byId.get(judgment.candidateId) ?? [];
    entries.push(judgment);
    byId.set(judgment.candidateId, entries);
  }
  return candidateIds.map((candidateId) => {
    const entries = byId.get(candidateId) ?? [];
    if (entries.length === 0) {
      return fallbackJudgment(
        candidateId,
        "No normalized judgment was supplied; candidate requires review.",
      );
    }
    if (entries.length > 1) {
      return fallbackJudgment(
        candidateId,
        "Duplicate or conflicting normalized judgments were supplied; candidate requires review.",
      );
    }
    return sanitizeSuppliedJudgment(candidateId, entries[0]!);
  });
}

function connectedComponents(
  candidateIds: readonly string[],
  proposedGroups: readonly { candidateIds: readonly string[] }[],
): string[][] {
  const parent = new Map(candidateIds.map((candidateId) => [candidateId, candidateId]));

  function find(candidateId: string): string {
    const current = parent.get(candidateId)!;
    if (current === candidateId) {
      return current;
    }
    const root = find(current);
    parent.set(candidateId, root);
    return root;
  }

  function union(left: string, right: string): void {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot === rightRoot) {
      return;
    }
    const [first, second] = [leftRoot, rightRoot].sort();
    parent.set(second!, first!);
  }

  for (const group of proposedGroups) {
    const sorted = [...group.candidateIds].sort();
    const first = sorted[0];
    if (!first) {
      continue;
    }
    for (const candidateId of sorted.slice(1)) {
      union(first, candidateId);
    }
  }

  const groups = new Map<string, string[]>();
  for (const candidateId of [...candidateIds].sort()) {
    const root = find(candidateId);
    const group = groups.get(root) ?? [];
    group.push(candidateId);
    groups.set(root, group);
  }
  return [...groups.values()]
    .map((group) => group.sort())
    .sort((left, right) => left[0]!.localeCompare(right[0]!));
}

function canonicalCandidates<T extends MoaCandidateLike>(candidates: readonly T[]): T[] {
  const ids = new Set<string>();
  for (const candidate of candidates) {
    if (!candidate.candidateId.trim()) {
      throw new Error("MoA candidate ID cannot be empty.");
    }
    if (ids.has(candidate.candidateId)) {
      throw new Error(`Duplicate MoA candidate ID: ${candidate.candidateId}`);
    }
    ids.add(candidate.candidateId);
  }
  return [...candidates].sort((left, right) =>
    left.candidateId.localeCompare(right.candidateId)
  );
}

function uniqueCandidateIds(candidateIds: readonly string[]): string[] {
  const normalized = candidateIds
    .map((candidateId) => candidateId.trim())
    .filter(Boolean)
    .sort();
  return [...new Set(normalized)];
}

function rawJudgmentEntries(output: unknown): unknown[] {
  if (Array.isArray(output)) {
    return output;
  }
  if (isRecord(output) && Array.isArray(output.judgments)) {
    return output.judgments;
  }
  return [];
}

function rawAggregationGroups(output: unknown): unknown[] {
  if (Array.isArray(output)) {
    return output;
  }
  if (isRecord(output) && Array.isArray(output.groups)) {
    return output.groups;
  }
  return [];
}

function fallbackJudgment(
  candidateId: string,
  reason: string,
  reviewedBy?: string,
): MoaJudgment {
  return {
    candidateId,
    verdict: "needs-review",
    confidence: "low",
    reason,
    ...(reviewedBy ? { reviewedBy } : {}),
    source: "fallback",
  };
}

function sanitizeSuppliedJudgment(
  candidateId: string,
  judgment: MoaJudgment,
): MoaJudgment {
  const verdict = judgmentVerdict(judgment.verdict);
  const confidence = judgmentConfidence(judgment.confidence);
  const reason = normalizedString(judgment.reason, 400);
  if (!verdict || (verdict === "rejected" && (!confidence || !reason))) {
    return fallbackJudgment(
      candidateId,
      "Supplied rejection was malformed or incomplete; candidate requires review.",
      normalizedString(judgment.reviewedBy, 160),
    );
  }
  return {
    candidateId,
    verdict,
    confidence: confidence ?? "low",
    reason: reason ?? defaultJudgmentReason(verdict),
    ...(normalizedString(judgment.reviewedBy, 160)
      ? { reviewedBy: normalizedString(judgment.reviewedBy, 160)! }
      : {}),
    source: judgment.source === "judge" ? "judge" : "fallback",
  };
}

function defaultJudgmentReason(verdict: MoaJudgmentVerdict): string {
  if (verdict === "accepted") return "Judge accepted the cited evidence.";
  if (verdict === "rejected") return "Judge rejected the cited evidence.";
  return "Judge requested human review.";
}

function judgmentVerdict(value: unknown): MoaJudgmentVerdict | undefined {
  return value === "accepted" || value === "rejected" || value === "needs-review"
    ? value
    : undefined;
}

function judgmentConfidence(value: unknown): MoaJudgmentConfidence | undefined {
  return value === "low" || value === "medium" || value === "high"
    ? value
    : undefined;
}

function normalizedString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.replace(/\s+/gu, " ").trim();
  if (!normalized) {
    return undefined;
  }
  return normalized.slice(0, maxLength);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
