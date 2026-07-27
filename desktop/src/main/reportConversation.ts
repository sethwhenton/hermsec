export interface ConversationFinding {
  id?: string;
  title: string;
  severity: string;
  confidence?: string;
  category?: string;
  tool?: string;
  ruleId?: string;
  sourceLabel?: string;
  sourceLabels?: string[];
  judgeStatus?: string;
  location: string;
  description: string;
  remediation: string;
  code?: string;
}

export interface ConversationFindingIndexEntry {
  id?: string;
  title: string;
  severity: string;
  location: string;
  tool?: string;
  sourceLabel?: string;
}

export interface ConversationDetectorSummary {
  scannerFindingCount?: number;
  agentFindingCount?: number;
  finalFindingCount: number;
  provenance: "recorded" | "inferred" | "unknown";
  scanners: Array<{
    name: string;
    status: string;
    findings: number;
    message?: string;
  }>;
  agents: Array<{
    id: string;
    label: string;
    role: string;
    status: string;
    provider?: string;
    model?: string;
  }>;
}

export interface ConversationEvidence {
  reportPath?: string;
  targetName: string;
  projectRoot?: string;
  generatedAt?: string;
  scan?: {
    mode?: string;
    terminalStatus?: string;
    degradationReasons: string[];
    generatedWithModel?: boolean;
    modelProvider?: string;
    modelFallbackReason?: string;
  };
  counts: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    secrets: number;
    scannerFailures: number;
  };
  detectorSummary?: ConversationDetectorSummary;
  findingCoverage?: {
    included: number;
    indexed?: number;
    total: number;
    truncated: boolean;
    indexTruncated?: boolean;
  };
  findingIndex?: ConversationFindingIndexEntry[];
  findings: ConversationFinding[];
  note?: string;
}

export interface ConversationHistoryMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ConversationAnswerValidation {
  ok: boolean;
  reason?: string;
}

export function historyBeforeCurrentQuestion(
  history: readonly ConversationHistoryMessage[],
  question: string,
): ConversationHistoryMessage[] {
  const messages = history
    .filter((message) => message.content.trim())
    .map((message) => ({ role: message.role, content: message.content }));
  const last = messages.at(-1);
  if (
    last?.role === "user" &&
    normalizeConversationText(last.content) === normalizeConversationText(question)
  ) {
    messages.pop();
  }
  return messages;
}

export function inferDetectorFindingCounts(
  findings: ReadonlyArray<{
    sourceLabel?: string;
    sourceLabels?: readonly string[];
  }>,
): { scannerFindingCount: number; agentFindingCount: number } | undefined {
  if (findings.length === 0) {
    return { scannerFindingCount: 0, agentFindingCount: 0 };
  }

  let scannerFindingCount = 0;
  let agentFindingCount = 0;
  for (const finding of findings) {
    const labels = uniqueNonEmpty([
      finding.sourceLabel,
      ...(finding.sourceLabels ?? []),
    ]);
    if (labels.length === 0) return undefined;

    const hasAgentSource = labels.some(isAgentSource);
    const hasScannerSource = labels.some((label) => !isAgentSource(label));
    if (hasAgentSource) agentFindingCount += 1;
    if (hasScannerSource) scannerFindingCount += 1;
  }

  return { scannerFindingCount, agentFindingCount };
}

export function buildConversationalFallback(
  question: string,
  evidence: ConversationEvidence,
  history: readonly ConversationHistoryMessage[] = [],
): string {
  const lower = question.toLowerCase();
  const top = evidence.findings[0];

  if (/\b(what can you do|help|capabilities|commands|how do you work|what is hermsec|about hermsec|what does hermsec do|scan modes?)\b/.test(lower)) {
    return [
      "HermSec is a local-first desktop security assistant for code projects.",
      "It inspects a selected folder, chooses matching scanner tools, runs defensive checks, validates evidence, and writes readable reports.",
      "",
      "Main features:",
      "- Project inspection for languages, manifests, lockfiles, and config files.",
      "- Adaptive scanner setup for the tools a project needs.",
      "- Doctor checks for scanner readiness, model providers, and internet sources.",
      "- Live chat progress while scans run.",
      "- Reports in dashboard, JSON, Markdown, HTML, and PDF formats.",
      "- Automations for recurring scans while HermSec is open.",
      "",
      "Scan modes:",
      "- Scanner only: deterministic scanner evidence without a model provider.",
      "- Single agent: one model inspects focused code candidates without scanner tools.",
      "- MoA Low / High: three or five specialists, a false-positive judge, and an aggregator inspect candidates without scanner tools.",
      "- Scanner + Single / Scanner + MoA Low / High: independent scanner and agent paths, followed by deterministic evidence fusion.",
    ].join("\n");
  }

  if (!top) {
    if (evidence.note) {
      return [
        "I am available.",
        `I can answer questions about ${evidence.targetName}, configure scans or automations, explain HermSec behavior, and review exact findings after a scan is available.`,
        "",
        "Available actions: scan this project, set an automation, explain the app, or review security risks.",
      ].join("\n");
    }
    return [
      `The latest scan for ${evidence.targetName} did not record findings in the report artifacts I can read.`,
      "That is useful evidence, but it is not proof of perfect safety. Rerun the scan after meaningful dependency, authentication, or input-handling changes.",
    ].join("\n");
  }

  if (
    /\b(agent|agents|scanner|scanners)\b/.test(lower) &&
    /\b(find|found|finding|findings|result|results|contribut|produced)\w*\b/.test(
      lower,
    )
  ) {
    return buildDetectorSourceAnswer(evidence);
  }

  if (asksForOtherFindings(lower, history)) {
    return buildRemainingFindingsAnswer(evidence, history);
  }

  if (/\b(where|line|file|show|code)\b/.test(lower)) {
    return [
      `Here are the clearest places to start in ${evidence.targetName}:`,
      ...evidence.findings.slice(0, 5).map((finding, index) =>
        [
          `${index + 1}. ${finding.severity}: ${finding.title}`,
          `   Where: ${finding.location}`,
          finding.code ? `   Code: ${finding.code}` : "",
          `   Why: ${finding.description}`,
        ].filter(Boolean).join("\n"),
      ),
      "",
      "Name one of these findings and I can explain the evidence, impact, and safe patch.",
    ].join("\n");
  }

  if (/\b(fix|patch|remed|first|priority|next)\b/.test(lower)) {
    return [
      `I would start with the highest-impact finding in ${evidence.targetName}: ${top.severity} - ${top.title}.`,
      `Location: ${top.location}`,
      top.code ? `Code: ${top.code}` : "",
      "",
      `Why it matters: ${top.description}`,
      `Fix direction: ${top.remediation}`,
      "",
      "After patching, rerun the scan and compare the dashboard.",
    ].filter(Boolean).join("\n");
  }

  if (/\b(have you|scanned|scan|report|found)\b/.test(lower)) {
    return [
      `I have the latest saved report for ${evidence.targetName}.`,
      `It contains ${evidence.counts.total} findings: ${evidence.counts.critical} critical, ${evidence.counts.high} high, ${evidence.counts.medium} medium, ${evidence.counts.low} low, and ${evidence.counts.info} info.`,
      `The highest-priority issue is ${top.severity} - ${top.title} at ${top.location}.`,
      "",
      "Ask for the remaining findings, exact locations, or a remediation order.",
    ].join("\n");
  }

  return [
    `The current report for ${evidence.targetName} contains ${evidence.counts.total} findings.`,
    `The first issue I would inspect is ${top.severity} - ${top.title} at ${top.location}.`,
    "",
    `What it means: ${top.description}`,
    `Fix direction: ${top.remediation}`,
    "",
    "Ask for the remaining findings or name this one for a deeper explanation.",
  ].join("\n");
}

export function validateConversationModelAnswer({
  answer,
  question,
  evidence,
  history,
}: {
  answer: string;
  question: string;
  evidence: ConversationEvidence;
  history: readonly ConversationHistoryMessage[];
}): ConversationAnswerValidation {
  const priorAssistantAnswers = history
    .filter((message) => message.role === "assistant")
    .map((message) => message.content)
    .filter(Boolean);
  if (
    !/\b(repeat|restate|quote|verbatim|say that again)\b/i.test(question) &&
    priorAssistantAnswers.some((previous) =>
      isNearDuplicateConversationAnswer(answer, previous),
    )
  ) {
    return {
      ok: false,
      reason: "The answer repeats a prior assistant response instead of addressing the follow-up.",
    };
  }

  const unknownLocation = preciseLocations(answer).find(
    (location) => !knownPreciseLocations(evidence).has(normalizeLocation(location)),
  );
  if (unknownLocation) {
    return {
      ok: false,
      reason: `The answer cites ${unknownLocation}, which is not a recorded finding location.`,
    };
  }

  const unknownFindingId = explicitFindingIds(answer).find(
    (id) => !knownFindingIds(evidence).has(id.toLowerCase()),
  );
  if (unknownFindingId) {
    return {
      ok: false,
      reason: `The answer cites finding id ${unknownFindingId}, which is not in the evidence packet.`,
    };
  }

  const reportCountError = validateReportFindingCountClaims(answer, evidence);
  if (reportCountError) {
    return { ok: false, reason: reportCountError };
  }
  const severityClaimError = validateFindingSeverityClaims(answer, evidence);
  if (severityClaimError) {
    return { ok: false, reason: severityClaimError };
  }
  const detectorClaimError = validateDetectorCountClaims(answer, evidence);
  if (detectorClaimError) {
    return { ok: false, reason: detectorClaimError };
  }
  const detectorStatusError = validateDetectorStatusClaims(answer, evidence);
  if (detectorStatusError) {
    return { ok: false, reason: detectorStatusError };
  }

  if (asksForOtherFindings(question.toLowerCase(), history)) {
    const remaining = remainingFindingEntries(evidence, history, true);
    const allEntries = allFindingEntries(evidence);
    if (
      remaining.length > 0 &&
      !remaining.some((finding) =>
        answerMentionsFinding(answer, finding, allEntries),
      )
    ) {
      return {
        ok: false,
        reason: "The answer does not identify any remaining finding from the evidence packet.",
      };
    }
  }

  return { ok: true };
}

export function isNearDuplicateConversationAnswer(
  candidate: string,
  previous: string,
): boolean {
  const candidateText = normalizeAnswerForComparison(candidate);
  const previousText = normalizeAnswerForComparison(previous);
  if (!candidateText || !previousText) return false;
  const candidateTokens = candidateText.split(" ");
  const previousTokens = previousText.split(" ");
  if (candidateText === previousText) {
    return Math.min(candidateTokens.length, previousTokens.length) >= 12;
  }
  if (Math.min(candidateTokens.length, previousTokens.length) < 30) return false;

  const lengthRatio = candidateTokens.length / previousTokens.length;
  if (lengthRatio < 0.8 || lengthRatio > 1.25) return false;

  const candidateShingles = tokenShingles(candidateTokens, 4);
  const previousShingles = tokenShingles(previousTokens, 4);
  const intersection = [...candidateShingles].filter((value) =>
    previousShingles.has(value),
  ).length;
  const union = new Set([...candidateShingles, ...previousShingles]).size;
  const smaller = Math.min(candidateShingles.size, previousShingles.size);
  const jaccard = union > 0 ? intersection / union : 0;
  const containment = smaller > 0 ? intersection / smaller : 0;
  return jaccard >= 0.85 || containment >= 0.94;
}

export function addFindingCoverageDisclosure(
  answer: string,
  question: string,
  evidence: ConversationEvidence,
): string {
  const coverage = evidence.findingCoverage;
  if (
    !coverage?.truncated ||
    !/\b(all|every|other|else|rest|remaining|more|complete|full list|keep going)\b/i.test(
      question,
    )
  ) {
    return answer;
  }

  const disclosure = `Coverage note: detailed evidence is loaded for ${coverage.included} of ${coverage.total} findings; use the full report for findings outside that detailed set.`;
  if (
    answer.includes(`${coverage.included} of ${coverage.total}`) ||
    answer.toLowerCase().includes("coverage note:")
  ) {
    return answer;
  }
  return `${answer.trim()}\n\n${disclosure}`;
}

function buildRemainingFindingsAnswer(
  evidence: ConversationEvidence,
  history: readonly ConversationHistoryMessage[],
): string {
  const pageSize = 6;
  const remaining = remainingFindingEntries(evidence, history, true);
  const page = remaining.slice(0, pageSize);
  const coverage = evidence.findingCoverage;
  const indexedCount =
    evidence.findingIndex?.length ??
    coverage?.indexed ??
    evidence.findings.length;
  const unindexedCount = Math.max(
    0,
    (coverage?.total ?? indexedCount) - indexedCount,
  );

  if (page.length === 0) {
    if (unindexedCount > 0) {
      return [
        `We have covered every finding in the loaded index for ${evidence.targetName}.`,
        `${unindexedCount} additional findings exist in the full report, but their titles and locations were not loaded into this conversation.`,
        "Open the full report to review that remaining set accurately.",
      ].join("\n");
    }
    return `We have covered all ${coverage?.total ?? indexedCount} findings recorded for ${evidence.targetName}.`;
  }

  const knownAfterPage = Math.max(0, remaining.length - page.length);
  const followOnCount = knownAfterPage + unindexedCount;
  const hasPriorAssistant = history.some(
    (message) => message.role === "assistant",
  );
  return [
    hasPriorAssistant
      ? "Here are the next findings we have not covered yet:"
      : `Here are the findings in priority order for ${evidence.targetName}:`,
    ...page.map((finding, index) => formatFindingLine(finding, index + 1)),
    ...(followOnCount > 0
      ? [`${followOnCount} more findings remain after this group.`]
      : []),
    ...(coverage?.truncated
      ? [
          `Detailed explanations are loaded for ${coverage.included} of ${coverage.total} findings; the full report remains the source of record for the rest.`,
        ]
      : []),
    "",
    "Name one of these findings and I can explain its evidence, likely impact, and remediation.",
  ].join("\n");
}

function buildDetectorSourceAnswer(evidence: ConversationEvidence): string {
  const detector = evidence.detectorSummary;
  if (!detector) {
    return [
      `The saved report for ${evidence.targetName} contains ${evidence.counts.total} final findings.`,
      "It does not include enough detector provenance to separate scanner findings from agent findings reliably.",
    ].join("\n");
  }

  const agentSummary =
    detector.agents.length > 0
      ? detector.agents.map((agent) => {
          const model = [agent.provider, agent.model].filter(Boolean).join(" / ");
          return `- ${agent.label || agent.id}: ${agent.status}${model ? ` (${model})` : ""}`;
        })
      : ["- No agent execution was recorded."];
  const scannerSummary =
    detector.scanners.length > 0
      ? detector.scanners.map(
          (scanner) => `- ${scanner.name}: ${scanner.findings} findings (${scanner.status})`,
        )
      : ["- Scanner-level counts were not recorded."];

  return [
    `The saved run for ${evidence.targetName} produced ${detector.finalFindingCount} final findings.`,
    detectorCountsLine(detector),
    ...(evidence.scan?.terminalStatus
      ? [
          `Run status: ${evidence.scan.terminalStatus}${
            evidence.scan.degradationReasons.length > 0
              ? ` (${evidence.scan.degradationReasons.join(", ")})`
              : ""
          }.`,
        ]
      : []),
    "",
    "Agent path:",
    ...agentSummary,
    ...(evidence.scan?.modelFallbackReason
      ? [`- Scan-agent note: ${evidence.scan.modelFallbackReason}`]
      : []),
    "",
    "Scanner breakdown:",
    ...scannerSummary,
    "",
    "Highest-priority saved findings:",
    ...evidence.findings.slice(0, 5).map((finding, index) =>
      formatFindingLine(finding, index + 1),
    ),
  ].join("\n");
}

function detectorCountsLine(detector: ConversationDetectorSummary): string {
  const scanner = detector.scannerFindingCount;
  const agent = detector.agentFindingCount;
  if (typeof scanner === "number" && typeof agent === "number") {
    if (detector.provenance === "inferred") {
      return `Based on finding source labels, scanners contributed ${scanner}; model agents contributed ${agent}.`;
    }
    return `Scanners contributed ${scanner}; model agents contributed ${agent}.`;
  }
  if (typeof scanner === "number") {
    return `The artifacts record ${scanner} scanner findings, but do not record a reliable agent-finding count.`;
  }
  if (typeof agent === "number") {
    return `The artifacts record ${agent} agent findings, but do not record a reliable scanner-finding count.`;
  }
  return "This report does not contain enough provenance to split the final findings between scanners and model agents reliably.";
}

function remainingFindingEntries(
  evidence: ConversationEvidence,
  history: readonly ConversationHistoryMessage[],
  skipTopWhenUnmentioned: boolean,
): ConversationFindingIndexEntry[] {
  const entries = allFindingEntries(evidence);
  const discussed = discussedFindingIndexes(entries, history);
  if (
    skipTopWhenUnmentioned &&
    discussed.size === 0 &&
    entries.length > 0 &&
    history.some((message) => message.role === "assistant")
  ) {
    discussed.add(0);
  }
  return entries.filter((_, index) => !discussed.has(index));
}

function allFindingEntries(
  evidence: ConversationEvidence,
): ConversationFindingIndexEntry[] {
  if (evidence.findingIndex?.length) return evidence.findingIndex;
  return evidence.findings.map((finding) => ({
    ...(finding.id ? { id: finding.id } : {}),
    title: finding.title,
    severity: finding.severity,
    location: finding.location,
    ...(finding.tool ? { tool: finding.tool } : {}),
    ...(finding.sourceLabel ? { sourceLabel: finding.sourceLabel } : {}),
  }));
}

function discussedFindingIndexes(
  entries: readonly ConversationFindingIndexEntry[],
  history: readonly ConversationHistoryMessage[],
): Set<number> {
  const discussed = new Set<number>();
  const titleCounts = findingTitleCounts(entries);
  for (const message of history) {
    const content = message.content.toLowerCase();
    const normalized = normalizeAnchorText(message.content);
    entries.forEach((finding, index) => {
      const normalizedTitle = normalizeAnchorText(finding.title);
      const titleIsUnique = titleCounts.get(normalizedTitle) === 1;
      if (
        (finding.id && containsAnchor(normalized, finding.id)) ||
        (titleIsUnique && containsAnchor(normalized, finding.title)) ||
        (finding.location && content.includes(finding.location.toLowerCase()))
      ) {
        discussed.add(index);
      }
    });
  }
  return discussed;
}

function answerMentionsFinding(
  answer: string,
  finding: ConversationFindingIndexEntry,
  allEntries: readonly ConversationFindingIndexEntry[],
): boolean {
  const normalized = normalizeAnchorText(answer);
  const normalizedTitle = normalizeAnchorText(finding.title);
  const titleIsUnique =
    findingTitleCounts(allEntries).get(normalizedTitle) === 1;
  return Boolean(
    (finding.id && containsAnchor(normalized, finding.id)) ||
      (titleIsUnique && containsAnchor(normalized, finding.title)) ||
      (finding.location &&
        answer.toLowerCase().includes(finding.location.toLowerCase())),
  );
}

function findingTitleCounts(
  entries: readonly ConversationFindingIndexEntry[],
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const finding of entries) {
    const title = normalizeAnchorText(finding.title);
    counts.set(title, (counts.get(title) ?? 0) + 1);
  }
  return counts;
}

function containsAnchor(normalizedContent: string, anchor: string): boolean {
  const normalizedAnchor = normalizeAnchorText(anchor);
  return normalizedAnchor.length >= 4 && normalizedContent.includes(normalizedAnchor);
}

function formatFindingLine(
  finding: ConversationFindingIndexEntry,
  index: number,
): string {
  const source = finding.tool || finding.sourceLabel;
  return `${index}. ${finding.severity}: ${finding.title} - ${finding.location}${
    source ? ` [${source}]` : ""
  }`;
}

function validateDetectorCountClaims(
  answer: string,
  evidence: ConversationEvidence,
): string | undefined {
  const detector = evidence.detectorSummary;
  if (!detector) return undefined;
  const claims = [
    {
      label: "scanner",
      expected: detector.scannerFindingCount,
      patterns: [
        /\bscanners?\s+(?:contributed|found|produced|reported)\s+(\d+)\b/giu,
        /\b(\d+)\s+(?:scanner findings?|findings?\s+from\s+scanners?)\b/giu,
      ],
    },
    {
      label: "agent",
      expected: detector.agentFindingCount,
      patterns: [
        /\b(?:model\s+)?agents?\s+(?:contributed|found|produced|reported)\s+(\d+)\b/giu,
        /\b(\d+)\s+(?:agent findings?|findings?\s+from\s+(?:model\s+)?agents?)\b/giu,
      ],
    },
  ];

  for (const claim of claims) {
    if (typeof claim.expected !== "number") continue;
    for (const pattern of claim.patterns) {
      for (const match of answer.matchAll(pattern)) {
        const claimed = Number(match[1]);
        if (claimed !== claim.expected) {
          return `The answer claims ${claimed} ${claim.label} findings, but the recorded count is ${claim.expected}.`;
        }
      }
    }
  }
  return undefined;
}

function validateReportFindingCountClaims(
  answer: string,
  evidence: ConversationEvidence,
): string | undefined {
  const patterns = [
    /\b(?:report|scan|run)\s+(?:has|contains|found|recorded|reported|produced|returned)\s+(\d+)\s+(?:total\s+)?findings?\b/giu,
    /\bthere\s+(?:are|were)\s+(\d+)\s+(?:total\s+)?findings?\b/giu,
    /\b(\d+)\s+findings?\s+(?:in|on)\s+the\s+(?:report|scan)\b/giu,
  ];
  for (const pattern of patterns) {
    for (const match of answer.matchAll(pattern)) {
      const claimed = Number(match[1]);
      if (claimed !== evidence.counts.total) {
        return `The answer claims ${claimed} total findings, but the report records ${evidence.counts.total}.`;
      }
    }
  }
  return undefined;
}

function validateFindingSeverityClaims(
  answer: string,
  evidence: ConversationEvidence,
): string | undefined {
  const entries = allFindingEntries(evidence);
  const titleCounts = findingTitleCounts(entries);
  const segments = answer
    .split(/\r?\n|(?<=[.!?])\s+/u)
    .map((segment) => segment.trim())
    .filter(Boolean);

  for (const finding of entries) {
    const expected = finding.severity.trim().toLowerCase();
    const normalizedTitle = normalizeAnchorText(finding.title);
    const titleIsUnique = titleCounts.get(normalizedTitle) === 1;
    for (const segment of segments) {
      const normalizedSegment = normalizeAnchorText(segment);
      const mentionsFinding =
        (finding.id && containsAnchor(normalizedSegment, finding.id)) ||
        (titleIsUnique && containsAnchor(normalizedSegment, finding.title)) ||
        (finding.location &&
          segment.toLowerCase().includes(finding.location.toLowerCase()));
      if (!mentionsFinding) continue;

      const severityClaims = [
        ...segment.matchAll(
          /\b(critical|high|medium|low|info)(?:[- ]severity|(?=\s*[:\u2014])|(?=\s+-\s+))/giu,
        ),
      ].map((match) => match[1].toLowerCase());
      if (
        severityClaims.length > 0 &&
        !severityClaims.includes(expected)
      ) {
        return `The answer assigns ${severityClaims.join("/")} severity to ${finding.title}, but the report records ${expected.toUpperCase()}.`;
      }
    }
  }
  return undefined;
}

function validateDetectorStatusClaims(
  answer: string,
  evidence: ConversationEvidence,
): string | undefined {
  const detector = evidence.detectorSummary;
  const normalized = normalizeAnswerForComparison(answer);
  const successfulStatuses = new Set([
    "completed",
    "success",
    "succeeded",
    "ready",
  ]);
  const failedStatuses = new Set([
    "failed",
    "error",
    "unavailable",
    "timed-out",
    "timeout",
  ]);

  const agentStatuses =
    detector?.agents.map((agent) => agent.status.trim().toLowerCase()) ?? [];
  const namedAgentStatusError = validateNamedDetectorStatusClaims(
    answer,
    detector?.agents.map((agent) => ({
      displayName: agent.label || agent.id,
      aliases: [agent.label, agent.id],
      status: agent.status,
    })) ?? [],
    "agent",
    successfulStatuses,
    failedStatuses,
  );
  if (namedAgentStatusError) return namedAgentStatusError;
  const claimsAllAgentSuccess =
    /\b(?:all agents?|agent path) (?:completed successfully|completed|succeeded|ran successfully)\b/u.test(
      normalized,
    );
  const claimsSingleAgentSuccess =
    agentStatuses.length === 1 &&
    /\b(?:the |model )agent (?:completed successfully|completed|succeeded|ran successfully)\b/u.test(
      normalized,
    );
  const claimsAllAgentFailure =
    /\b(?:all agents?|agent path) (?:failed|errored|timed out)\b/u.test(
      normalized,
    );
  const claimsSingleAgentFailure =
    agentStatuses.length === 1 &&
    /\b(?:the |model )agent (?:failed|errored|timed out)\b/u.test(
      normalized,
    );
  if (
    (claimsAllAgentSuccess || claimsSingleAgentSuccess) &&
    agentStatuses.length > 0 &&
    agentStatuses.some((status) => !successfulStatuses.has(status))
  ) {
    return `The answer says the agent path succeeded, but the recorded agent status is ${agentStatuses.join(", ")}.`;
  }
  if (
    (claimsAllAgentFailure || claimsSingleAgentFailure) &&
    agentStatuses.length > 0 &&
    agentStatuses.some((status) => !failedStatuses.has(status))
  ) {
    return `The answer says the agent path failed, but the recorded agent status is ${agentStatuses.join(", ")}.`;
  }

  const scannerStatuses =
    detector?.scanners.map((scanner) => scanner.status.trim().toLowerCase()) ??
    [];
  const namedScannerStatusError = validateNamedDetectorStatusClaims(
    answer,
    detector?.scanners.map((scanner) => ({
      displayName: scanner.name,
      aliases: [scanner.name],
      status: scanner.status,
    })) ?? [],
    "scanner",
    successfulStatuses,
    failedStatuses,
  );
  if (namedScannerStatusError) return namedScannerStatusError;
  const claimsAllScannerSuccess =
    /\b(?:all scanners?|scanner path) (?:completed successfully|completed without errors|succeeded|ran successfully|passed)\b/u.test(
      normalized,
    );
  const claimsSingleScannerSuccess =
    scannerStatuses.length === 1 &&
    /\b(?:the |a )scanner (?:completed successfully|completed without errors|succeeded|ran successfully|passed)\b/u.test(
      normalized,
    );
  const claimsAllScannerFailure =
    /\b(?:all scanners?|scanner path) (?:failed|errored|timed out)\b/u.test(
      normalized,
    );
  const claimsSingleScannerFailure =
    scannerStatuses.length === 1 &&
    /\b(?:the |a )scanner (?:failed|errored|timed out)\b/u.test(
      normalized,
    );
  if (
    (claimsAllScannerSuccess || claimsSingleScannerSuccess) &&
    scannerStatuses.length > 0 &&
    scannerStatuses.some((status) => !successfulStatuses.has(status))
  ) {
    return `The answer says the scanner path succeeded, but recorded scanner statuses are ${scannerStatuses.join(", ")}.`;
  }
  if (
    (claimsAllScannerFailure || claimsSingleScannerFailure) &&
    scannerStatuses.length > 0 &&
    scannerStatuses.some((status) => !failedStatuses.has(status))
  ) {
    return `The answer says a scanner failed, but recorded scanner statuses are ${scannerStatuses.join(", ")}.`;
  }

  const runStatus = evidence.scan?.terminalStatus?.trim().toLowerCase();
  const claimsRunSuccess =
    /\b(?:scan|run) (?:completed successfully|succeeded|was successful|is successful)\b/u.test(
      normalized,
    );
  const claimsRunDegraded =
    /\b(?:scan|run) (?:was |is |ended )?(?:partial|degraded|failed)\b/u.test(
      normalized,
    );
  if (
    claimsRunSuccess &&
    runStatus &&
    !successfulStatuses.has(runStatus)
  ) {
    return `The answer says the run succeeded, but the recorded terminal status is ${runStatus}.`;
  }
  if (
    claimsRunDegraded &&
    runStatus &&
    successfulStatuses.has(runStatus) &&
    (evidence.scan?.degradationReasons.length ?? 0) === 0
  ) {
    return `The answer says the run was degraded, but the recorded terminal status is ${runStatus} with no degradation reason.`;
  }
  return undefined;
}

function validateNamedDetectorStatusClaims(
  answer: string,
  records: ReadonlyArray<{
    displayName: string;
    aliases: readonly string[];
    status: string;
  }>,
  kind: "agent" | "scanner",
  successfulStatuses: ReadonlySet<string>,
  failedStatuses: ReadonlySet<string>,
): string | undefined {
  const aliasCounts = new Map<string, number>();
  for (const record of records) {
    const normalizedAliases = new Set(
      uniqueNonEmpty(record.aliases).map(normalizeAnchorText),
    );
    for (const normalizedAlias of normalizedAliases) {
      aliasCounts.set(
        normalizedAlias,
        (aliasCounts.get(normalizedAlias) ?? 0) + 1,
      );
    }
  }
  const segments = answer
    .split(/\r?\n|;|(?<=[.!?])\s+|\b(?:while|whereas|but)\b/iu)
    .map((segment) => segment.trim())
    .filter(Boolean);
  const recordAliases = records.map((record) =>
    [
      ...new Map(
        uniqueNonEmpty(record.aliases).map((alias) => [
          normalizeAnchorText(alias),
          alias,
        ]),
      ).entries(),
    ]
      .filter(
        ([normalizedAlias]) =>
          normalizedAlias.trim().length >= 4 &&
          aliasCounts.get(normalizedAlias) === 1,
      )
      .map(([, alias]) => alias),
  );

  for (const [recordIndex, record] of records.entries()) {
    const status = record.status.trim().toLowerCase();
    const aliases = recordAliases[recordIndex];
    for (const segment of segments) {
      const normalizedSegment = normalizeAnchorText(segment);
      if (
        !aliases.some((alias) => containsAnchor(normalizedSegment, alias))
      ) {
        continue;
      }
      const mentionedRecordCount = recordAliases.filter((candidateAliases) =>
        candidateAliases.some((alias) =>
          containsAnchor(normalizedSegment, alias),
        ),
      ).length;
      if (mentionedRecordCount > 1) continue;
      const normalizedStatusText = normalizeAnswerForComparison(segment);
      const claimsSuccess =
        /\b(?:completed successfully|completed|succeeded|ran successfully|passed)\b/u.test(
          normalizedStatusText,
        );
      const claimsFailure =
        /\b(?:failed|errored|timed out)\b/u.test(normalizedStatusText);
      if (claimsSuccess && !successfulStatuses.has(status)) {
        return `The answer says ${record.displayName} succeeded, but its recorded ${kind} status is ${status}.`;
      }
      if (claimsFailure && !failedStatuses.has(status)) {
        return `The answer says ${record.displayName} failed, but its recorded ${kind} status is ${status}.`;
      }
    }
  }
  return undefined;
}

function preciseLocations(value: string): string[] {
  return value.match(
    /\b(?:[A-Za-z0-9_.-]+[\\/])*[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,10}:\d+\b/gu,
  ) ?? [];
}

function knownPreciseLocations(evidence: ConversationEvidence): Set<string> {
  return new Set(
    allFindingEntries(evidence)
      .map((finding) => finding.location)
      .filter((location) => /:\d+$/u.test(location))
      .map(normalizeLocation),
  );
}

function normalizeLocation(value: string): string {
  return value.trim().replace(/\\/g, "/").toLowerCase();
}

function explicitFindingIds(value: string): string[] {
  return [...value.matchAll(/\bfinding\s+(?:id\s*[:=]\s*|#)([A-Za-z0-9][A-Za-z0-9_.:-]{2,})/giu)]
    .map((match) => match[1])
    .filter(Boolean);
}

function knownFindingIds(evidence: ConversationEvidence): Set<string> {
  return new Set(
    allFindingEntries(evidence)
      .map((finding) => finding.id?.toLowerCase())
      .filter((id): id is string => Boolean(id)),
  );
}

function asksForOtherFindings(
  lowerQuestion: string,
  history: readonly ConversationHistoryMessage[] = [],
): boolean {
  const explicitFindingRequest =
    /\b(other|others|else|remaining|more|next)\b/.test(lowerQuestion) &&
    /\b(finding|findings|issue|issues|risk|risks)\b/.test(lowerQuestion);
  if (explicitFindingRequest) return true;

  const hasPriorAssistant = history.some(
    (message) => message.role === "assistant",
  );
  if (!hasPriorAssistant) return false;
  return /^\s*(?:anything else|what else|and (?:the )?rest|the rest|keep going|go on|continue|more|next)\s*[?.!]*\s*$/iu.test(
    lowerQuestion,
  );
}

function isAgentSource(value: string): boolean {
  return /\b(agent|specialist|aggregator|judge)\b/i.test(value);
}

function uniqueNonEmpty(values: ReadonlyArray<string | undefined>): string[] {
  return [
    ...new Set(
      values
        .map((value) => value?.trim())
        .filter((value): value is string => Boolean(value)),
    ),
  ];
}

function normalizeConversationText(value: string): string {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function normalizeAnswerForComparison(value: string): string {
  return value
    .toLowerCase()
    .replace(/\bconversation model note:[\s\S]*$/u, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeAnchorText(value: string): string {
  return ` ${value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()} `;
}

function tokenShingles(tokens: readonly string[], width: number): Set<string> {
  const shingles = new Set<string>();
  for (let index = 0; index <= tokens.length - width; index += 1) {
    shingles.add(tokens.slice(index, index + width).join(" "));
  }
  return shingles;
}
