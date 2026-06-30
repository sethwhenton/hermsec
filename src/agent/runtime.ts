import crypto from "node:crypto";
import { explainFindingsWithoutModel, summarizeFindingsWithoutModel } from "../model/noModel.js";
import type { ModelProviderAdapter, ModelRequest, ProviderConfig } from "../model/provider.js";
import type { Finding } from "../shared/types.js";
import { redactForModel } from "./redaction.js";
import { routeAgentIntent, type AgentIntent } from "./intentRouter.js";
import { hermsecSystemPrompt } from "./systemPrompt.js";
import {
  parseModelExplanation,
  validateModelExplanation,
  type ModelExplanation
} from "./structuredOutput.js";

export type AgentTurnInput = {
  message: string;
  findings?: readonly Finding[];
  provider?: ModelProviderAdapter;
  providerConfig?: ProviderConfig;
  privacyMode?: "local-only" | "balanced" | "cloud-assisted";
  offlineMode?: boolean;
  forceIntent?: "explain_findings";
};

export type AgentTurnResult = {
  ok: boolean;
  intent: AgentIntent;
  message: string;
  refusalReason?: string;
  explanations?: Record<string, ModelExplanation>;
  priorityActions?: string[];
  providerUsed: string;
  modelSkippedReason?: string;
  evidenceUnchanged: boolean;
};

export async function runAgentTurn(input: AgentTurnInput): Promise<AgentTurnResult> {
  const findings = input.findings ?? [];
  const evidenceBefore = fingerprintFindings(findings);
  const route = input.forceIntent
    ? { intent: input.forceIntent, reason: "Hermsec scanner harness requested model explanation of completed scanner findings." }
    : routeAgentIntent(input.message);

  if (route.intent === "unsafe_or_out_of_scope") {
    return {
      ok: false,
      intent: route.intent,
      message: "Hermsec can summarize scanner evidence and recommend defensive fixes, but it cannot edit code, run shell commands, install packages, read secrets, or provide exploit steps.",
      refusalReason: route.reason,
      providerUsed: "none",
      evidenceUnchanged: evidenceBefore === fingerprintFindings(findings)
    };
  }

  if (route.intent === "explain_findings") {
    const selected = route.findingId
      ? findings.filter((finding) => finding.id.toLowerCase() === route.findingId?.toLowerCase())
      : findings;
    if (selected.length === 0) {
      return {
        ok: false,
        intent: route.intent,
        message: "I need an existing scanner finding before I can explain it.",
        providerUsed: "none",
        modelSkippedReason: "no-findings",
        evidenceUnchanged: evidenceBefore === fingerprintFindings(findings)
      };
    }
    return explainSelectedFindings(selected, input, evidenceBefore);
  }

  if (route.intent === "scan_target") {
    return passiveResult(route.intent, "Route this request to the scanner harness. The agent itself does not create findings or mutate scanner evidence.", evidenceBefore, findings);
  }
  if (route.intent === "show_report") {
    return passiveResult(route.intent, "Route this request to the local report index or report renderer.", evidenceBefore, findings);
  }
  if (route.intent === "configure_provider") {
    return passiveResult(route.intent, "Provider configuration must store only provider IDs and environment-variable references, never raw keys.", evidenceBefore, findings);
  }
  if (route.intent === "show_help") {
    return passiveResult(route.intent, "Hermsec can scan approved targets, explain existing findings, show local reports, configure workspaces/providers, and update trusted security intel.", evidenceBefore, findings);
  }
  return passiveResult(route.intent, "I need a workspace, scan ID, finding ID, or report target to continue safely.", evidenceBefore, findings);
}

async function explainSelectedFindings(
  findings: readonly Finding[],
  input: AgentTurnInput,
  evidenceBefore: string
): Promise<AgentTurnResult> {
  const fallback = explainFindingsWithoutModel(findings);
  const provider = input.provider;
  if (!provider || provider.id === "none" || input.offlineMode) {
    const summary = summarizeFindingsWithoutModel(findings);
    return {
      ok: true,
      intent: "explain_findings",
      message: summary.executiveSummary,
      explanations: fallback,
      priorityActions: summary.priorityActions,
      providerUsed: "none",
      modelSkippedReason: input.offlineMode ? "offline-mode" : "no-model",
      evidenceUnchanged: evidenceBefore === fingerprintFindings(input.findings ?? [])
    };
  }

  const selectedForModel = modelExplanationSelection(findings);
  const accepted: Record<string, ModelExplanation> = { ...fallback };
  const violations: string[] = [];
  const failures: string[] = [];
  let completedChunks = 0;

  await explainChunksWithModel({
    findings: selectedForModel,
    provider,
    providerConfig: input.providerConfig,
    fallback,
    accepted,
    violations,
    failures,
    totalWatchdogMs: modelWatchdogMs(input.providerConfig?.timeoutMs),
    onChunkCompleted: () => {
      completedChunks += 1;
    },
  });

  const summary = summarizeFindingsWithoutModel(findings);
  if (completedChunks === 0 && failures.length > 0) {
    const timedOut = failures.includes("model-summary-watchdog");
    return {
      ok: true,
      intent: "explain_findings",
      message: summary.executiveSummary,
      explanations: fallback,
      priorityActions: summary.priorityActions,
      providerUsed: "none",
      modelSkippedReason: timedOut ? "model-summary-watchdog" : "provider-failed",
      evidenceUnchanged: evidenceBefore === fingerprintFindings(input.findings ?? [])
    };
  }

  const limited = selectedForModel.length < findings.length
    ? ` Model explanations were generated for the top ${selectedForModel.length} prioritized finding(s); fallback evidence-bound explanations were used for the remaining ${findings.length - selectedForModel.length}.`
    : "";
  const partial = failures.length > 0 ? " Model explanation generation stopped early; fallback explanations were kept for unfinished chunks." : "";
  const message = violations.length > 0
    ? `${summary.executiveSummary} Some model text was rejected because it was not supported by scanner evidence; fallback explanations were used.${limited}${partial}`
    : `${summary.executiveSummary} Findings explained from supplied scanner evidence.${limited}${partial}`;
  return {
    ok: true,
    intent: "explain_findings",
    message,
    explanations: accepted,
    priorityActions: summary.priorityActions,
    providerUsed: provider.id,
    ...((violations.length > 0 || failures.length > 0)
      ? { modelSkippedReason: modelPartialReason(violations, failures) }
      : {}),
    evidenceUnchanged: evidenceBefore === fingerprintFindings(input.findings ?? [])
  };
}

async function explainChunksWithModel(options: {
  findings: readonly Finding[];
  provider: ModelProviderAdapter;
  providerConfig?: ProviderConfig | undefined;
  fallback: Record<string, ModelExplanation>;
  accepted: Record<string, ModelExplanation>;
  violations: string[];
  failures: string[];
  totalWatchdogMs: number;
  onChunkCompleted: () => void;
}): Promise<void> {
  const deadline = Date.now() + options.totalWatchdogMs;
  const chunkedFindings = chunks(options.findings, modelChunkSize());
  for (const [index, chunk] of chunkedFindings.entries()) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      options.failures.push("model-summary-watchdog");
      return;
    }
    const redactedEvidence = redactForModel(chunk);
    const request: ModelRequest = {
      messages: [
        { role: "system", content: hermsecSystemPrompt },
        {
          role: "user",
          content: [
            "Return ONLY one valid JSON object keyed by finding id.",
            `This is priority chunk ${index + 1} of ${chunkedFindings.length}.`,
            "Do not copy scanner objects back to me.",
            "Each top-level key must be one supplied finding id; never create new finding ids or merge findings.",
            "Each value must have exactly these explanation fields:",
            "{",
            '  "title": "short finding title",',
            '  "impact": "defensive impact using only scanner evidence",',
            '  "evidenceSummary": "what the scanner evidence says, including only supplied file/package/version/CVE/GHSA/OSV identifiers",',
            '  "suggestedFix": "safe defensive remediation from supplied evidence",',
            '  "confidenceReason": "why the scanner confidence is high/medium/low/confirmed",',
            '  "safeNextSteps": ["defensive next step 1", "defensive next step 2"],',
            '  "cveUsage": "from_evidence|not_applicable|not_present"',
            "}",
            "Use cveUsage=from_evidence only when the finding evidence includes a CVE.",
            "Use cveUsage=not_present for GHSA-only/package-only/code/secret findings without a CVE.",
            "Use cveUsage=not_applicable only when CVEs do not apply to the finding category.",
            "Use only this evidence:",
            JSON.stringify(redactedEvidence.value, null, 2),
          ].join("\n")
        }
      ],
      temperature: 0,
      maxTokens: 4000,
      responseFormat: "json"
    };

    let response: Awaited<ReturnType<ModelProviderAdapter["complete"]>>;
    try {
      response = await withTimeout(
        options.provider.complete(request, {
          ...options.providerConfig,
          timeoutMs: Math.min(options.providerConfig?.timeoutMs ?? modelChunkTimeoutMs(), modelChunkTimeoutMs(), remainingMs),
        }),
        Math.min(modelChunkTimeoutMs(), remainingMs),
        "model-summary-watchdog",
      );
    } catch (error) {
      options.failures.push(error instanceof Error ? error.message : String(error));
      return;
    }
    const parsed = parseExplanationMap(response.content);
    for (const finding of chunk) {
      const candidate = parsed[finding.id] ?? options.fallback[finding.id];
      if (!candidate) {
        options.accepted[finding.id] = options.fallback[finding.id]!;
        continue;
      }
      const validation = validateModelExplanation(finding, candidate);
      if (validation.ok) {
        options.accepted[finding.id] = validation.explanation;
      } else {
        options.accepted[finding.id] = options.fallback[finding.id]!;
        options.violations.push(...validation.violations);
      }
    }
    options.onChunkCompleted();
  }
}

function modelExplanationSelection(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindingsForModel).slice(0, modelFindingLimit());
}

function compareFindingsForModel(left: Finding, right: Finding): number {
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const categoryRank = { secret: 0, dependency: 1, "supply-chain": 2, code: 3, config: 4 };
  return (
    severityRank[left.severity] - severityRank[right.severity] ||
    categoryRank[left.category] - categoryRank[right.category] ||
    left.title.localeCompare(right.title) ||
    left.id.localeCompare(right.id)
  );
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    result.push(items.slice(index, index + size));
  }
  return result;
}

function modelFindingLimit(): number {
  return boundedEnvInt("HERMSEC_MODEL_FINDING_LIMIT", 120, 1, 500);
}

function modelChunkSize(): number {
  return boundedEnvInt("HERMSEC_MODEL_CHUNK_SIZE", 25, 1, 100);
}

function modelChunkTimeoutMs(): number {
  return boundedEnvInt("HERMSEC_MODEL_CHUNK_TIMEOUT_MS", 20_000, 1_000, 60_000);
}

function modelWatchdogMs(configuredTimeoutMs: number | undefined): number {
  return boundedEnvInt("HERMSEC_MODEL_SUMMARY_WATCHDOG_MS", Math.min(configuredTimeoutMs ?? 120_000, 120_000), 1_000, 300_000);
}

function modelPartialReason(violations: readonly string[], failures: readonly string[]): string {
  return [
    failures.includes("model-summary-watchdog") ? "model-summary-watchdog" : undefined,
    failures.some((failure) => failure !== "model-summary-watchdog") ? "provider-partial-failure" : undefined,
    violations.length > 0 ? "unsupported-model-output" : undefined,
  ].filter((item): item is string => item !== undefined).join("; ");
}

function boundedEnvInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

function parseExplanationMap(raw: string): Record<string, ModelExplanation> {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const result: Record<string, ModelExplanation> = {};
    for (const [id, value] of Object.entries(parsed)) {
      const explanation = parseModelExplanation(JSON.stringify(value));
      if (explanation) {
        result[id] = explanation;
      }
    }
    return result;
  } catch {
    return {};
  }
}

function passiveResult(
  intent: AgentIntent,
  message: string,
  evidenceBefore: string,
  findings: readonly Finding[]
): AgentTurnResult {
  return {
    ok: true,
    intent,
    message,
    providerUsed: "none",
    evidenceUnchanged: evidenceBefore === fingerprintFindings(findings)
  };
}

function fingerprintFindings(findings: readonly Finding[]): string {
  return crypto.createHash("sha256").update(JSON.stringify(findings)).digest("hex");
}
