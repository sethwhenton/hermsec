import type { ModelExplanation } from "../agent/structuredOutput.js";
import type { Finding } from "../shared/types.js";
import type { ModelProviderAdapter, ModelRequest, ModelResponse, ProviderConfig, ProviderHealth } from "./provider.js";

export type NoModelSummary = {
  executiveSummary: string;
  priorityActions: string[];
  explanations: Record<string, ModelExplanation>;
};

export const noModelProvider: ModelProviderAdapter = {
  id: "none",
  capabilities: {
    tools: false,
    jsonResponse: true,
    externalAbort: true,
    streaming: false,
  },
  async listModels() {
    return [{ id: "scanner-only", label: "Scanner-only fallback", local: true, supportsTools: false }];
  },
  async healthCheck(): Promise<ProviderHealth> {
    return {
      ok: true,
      provider: "none",
      message: "No model configured; deterministic scanner-only explanations are available.",
      credential: "not-required",
      local: true
    };
  },
  async complete(request: ModelRequest, _config?: ProviderConfig): Promise<ModelResponse> {
    if (
      (request.tools?.length ?? 0) > 0 ||
      request.messages.some((message) => message.role === "tool" || (message.role === "assistant" && (message.toolCalls?.length ?? 0) > 0))
    ) {
      throw new Error("none provider cannot execute agent tools.");
    }
    if (request.signal?.aborted) {
      throw request.signal.reason instanceof Error ? request.signal.reason : new Error("Model request was aborted.");
    }
    return {
      content: scannerOnlyResponse(request),
      model: "scanner-only",
      provider: "none",
      usage: {
        provider: "none",
        model: "scanner-only",
        local: true,
        estimatedUsd: 0
      }
    };
  },
  estimateCost() {
    return { estimatedUsd: 0, local: true };
  }
};

export function summarizeFindingsWithoutModel(findings: readonly Finding[]): NoModelSummary {
  const explanations = explainFindingsWithoutModel(findings);
  const sorted = [...findings].sort((left, right) => severityWeight[right.severity] - severityWeight[left.severity] || left.id.localeCompare(right.id));
  const priorityActions = sorted.slice(0, 5).map((finding) => {
    return `${finding.id}: ${finding.remediation || "Review and remediate according to scanner guidance."}`;
  });
  const counts = countBySeverity(findings);
  return {
    executiveSummary:
      findings.length === 0
        ? "No findings were reported by the configured scanners."
        : `${findings.length} scanner finding(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info.`,
    priorityActions,
    explanations
  };
}

export function explainFindingsWithoutModel(findings: readonly Finding[]): Record<string, ModelExplanation> {
  const result: Record<string, ModelExplanation> = {};
  for (const finding of findings) {
    result[finding.id] = explainFindingWithoutModel(finding);
  }
  return result;
}

export function explainFindingWithoutModel(finding: Finding): ModelExplanation {
  const identifiers = [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
    ...(finding.cwe ?? [])
  ];
  const location = finding.location
    ? ` at ${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : "";
  const identifierText = identifiers.length > 0 ? ` Identifiers supplied by scanner evidence: ${identifiers.join(", ")}.` : "";
  return {
    title: finding.title,
    impact: `${finding.severity.toUpperCase()} ${finding.category} finding reported by ${finding.tool}.`,
    evidenceSummary: `${finding.tool} reported ${finding.title}${location}. Evidence: ${finding.evidence}.${identifierText}`,
    suggestedFix: finding.remediation || "Review the finding and apply the minimal defensive fix recommended by the scanner or project maintainer.",
    confidenceReason: `Confidence is ${finding.confidence} because it comes from normalized scanner evidence; no additional vulnerabilities were inferred.`,
    safeNextSteps: [
      "Review the scanner evidence and affected location.",
      "Apply the smallest defensive change that addresses the reported issue.",
      "Run Hermsec again and compare the delta report."
    ],
    cveUsage: (finding.identifiers?.cve?.length ?? 0) > 0 ? "from_evidence" : "not_present"
  };
}

const severityWeight: Record<Finding["severity"], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

function countBySeverity(findings: readonly Finding[]): Record<Finding["severity"], number> {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );
}

function scannerOnlyResponse(request: ModelRequest): string {
  return JSON.stringify({
    title: "Scanner-only fallback",
    impact: "No model provider was used.",
    evidenceSummary: "Hermsec can render scanner evidence and deterministic remediation guidance without sending data to a model.",
    suggestedFix: "Review the normalized findings and rerun Hermsec after applying defensive fixes.",
    confidenceReason: `Response generated from ${request.messages.length} supplied message(s), without external model inference.`,
    safeNextSteps: ["Review scanner evidence.", "Apply a defensive fix.", "Rerun the scan."],
    cveUsage: "not_applicable"
  });
}
