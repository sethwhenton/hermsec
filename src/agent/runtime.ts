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
  const route = routeAgentIntent(input.message);

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

  const redactedEvidence = redactForModel(findings);
  const request: ModelRequest = {
    messages: [
      { role: "system", content: hermsecSystemPrompt },
      {
        role: "user",
        content: `Return one JSON object keyed by finding id. Each value must match ModelExplanation. Use only this evidence:\n${JSON.stringify(redactedEvidence.value, null, 2)}`
      }
    ],
    temperature: 0,
    responseFormat: "json"
  };

  try {
    const response = await provider.complete(request, input.providerConfig);
    const parsed = parseExplanationMap(response.content);
    const accepted: Record<string, ModelExplanation> = {};
    const violations: string[] = [];
    for (const finding of findings) {
      const candidate = parsed[finding.id] ?? fallback[finding.id];
      if (!candidate) {
        accepted[finding.id] = fallback[finding.id]!;
        continue;
      }
      const validation = validateModelExplanation(finding, candidate);
      if (validation.ok) {
        accepted[finding.id] = validation.explanation;
      } else {
        accepted[finding.id] = fallback[finding.id]!;
        violations.push(...validation.violations);
      }
    }
    return {
      ok: true,
      intent: "explain_findings",
      message: violations.length > 0 ? "Some model text was rejected because it was not supported by scanner evidence; fallback explanations were used." : "Findings explained from supplied scanner evidence.",
      explanations: accepted,
      priorityActions: summarizeFindingsWithoutModel(findings).priorityActions,
      providerUsed: provider.id,
      ...(violations.length > 0 ? { modelSkippedReason: "unsupported-model-output" } : {}),
      evidenceUnchanged: evidenceBefore === fingerprintFindings(input.findings ?? [])
    };
  } catch {
    const summary = summarizeFindingsWithoutModel(findings);
    return {
      ok: true,
      intent: "explain_findings",
      message: summary.executiveSummary,
      explanations: fallback,
      priorityActions: summary.priorityActions,
      providerUsed: "none",
      modelSkippedReason: "provider-failed",
      evidenceUnchanged: evidenceBefore === fingerprintFindings(input.findings ?? [])
    };
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
