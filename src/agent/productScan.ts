import { createCodeInspectionRuntime, type CodeInspectionRuntime, type CodeInspectionSnapshot } from "./codeInspection.js";
import { redactForModel } from "./redaction.js";
import { hermsecSystemPrompt } from "./systemPrompt.js";
import type { ModelProviderAdapter, ModelRequest, ProviderConfig } from "../model/provider.js";
import type { ReportAgentModeMetadata, ReportFindingSourceLabel } from "../reports/schema.js";
import { normalizeFinding } from "../scanners/normalization.js";
import { stableId } from "../shared/text.js";
import type { AgentFindingMetadata, Finding, FindingCategory, ScanAssistMode, ScannerStatus, Severity } from "../shared/types.js";

export type ProductAgentScanMode = Extract<ScanAssistMode, "single-agent" | "moa-assisted" | "scanner-moa-assisted">;
export type ProductAgentRoleId =
  | "single-agent-inspector"
  | "injection-and-execution"
  | "auth-and-data-flow"
  | "secrets-and-config"
  | "moa-false-positive-judge"
  | "moa-aggregator";

export type ProductAgentModelSelection = {
  provider: ModelProviderAdapter;
  providerConfig?: ProviderConfig;
};

export type ProductAgentScanInput = {
  repoRoot: string;
  mode: ProductAgentScanMode;
  provider: ModelProviderAdapter;
  providerConfig?: ProviderConfig;
  modelResolver?: (roleId: ProductAgentRoleId) => Promise<ProductAgentModelSelection | undefined>;
  scannerFindings?: Finding[];
};

export type ProductAgentScanResult =
  | {
      ok: true;
      findings: Finding[];
      status: ScannerStatus;
      provider: string;
      model?: string;
      limitations: string[];
      priorityActions: string[];
      executiveSummary: string;
      agentMode: ReportAgentModeMetadata;
    }
  | {
      ok: false;
      findings: [];
      status: ScannerStatus;
      provider: string;
      errorCode: "MODEL_PROVIDER_REQUIRED" | "MODEL_PROVIDER_FAILED" | "MODEL_OUTPUT_REJECTED";
      message: string;
      remediation: string;
      limitations: string[];
    };

type SpecialistRole = {
  id: string;
  label: string;
  focus: string;
  searchQueries: string[];
};

type RawAgentFinding = {
  candidateId?: unknown;
  title?: unknown;
  category?: unknown;
  severity?: unknown;
  confidence?: unknown;
  description?: unknown;
  evidence?: unknown;
  remediation?: unknown;
  ruleId?: unknown;
  cwe?: unknown;
  location?: unknown;
  sourceFindingIds?: unknown;
};

type CandidateFinding = {
  candidateId: string;
  finding: Finding;
};

type JudgeVerdict = "accepted" | "rejected" | "needs-review";

type JudgeResult = {
  candidateId: string;
  verdict: JudgeVerdict;
  confidence?: "low" | "medium" | "high";
  reason?: string;
};

const severityValues = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const categoryValues = new Set<FindingCategory>(["code", "dependency", "secret", "supply-chain", "config"]);
const confidenceValues = new Set<Finding["confidence"]>(["low", "medium", "high", "confirmed"]);

export const PRODUCT_AGENT_SPECIALISTS: readonly SpecialistRole[] = [
  {
    id: "injection-and-execution",
    label: "Injection and execution specialist",
    focus: "Find command execution, SQL/query injection, template injection, unsafe deserialization, and untrusted code evaluation risks.",
    searchQueries: ["exec(", "spawn(", "child_process", "shell=True", "subprocess.", "eval(", "Function(", "rawQuery", "SELECT ", "pickle.loads", "yaml.load"],
  },
  {
    id: "auth-and-data-flow",
    label: "Auth and data-flow specialist",
    focus: "Find unsafe authentication, authorization bypass, token validation, redirect, CORS, and sensitive data exposure risks.",
    searchQueries: ["jwt.verify", "authorize", "isAdmin", "redirect(", "cors(", "Access-Control-Allow-Origin", "session", "cookie", "password"],
  },
  {
    id: "secrets-and-config",
    label: "Secrets and config specialist",
    focus: "Find hardcoded secrets, insecure debug settings, weak security headers, and risky deployment configuration.",
    searchQueries: ["api_key", "secret", "token", "password", "DEBUG", "debug=True", "NODE_ENV", "helmet", "csrf"],
  },
] as const;

export async function runProductAgentScan(input: ProductAgentScanInput): Promise<ProductAgentScanResult> {
  if (!input.provider || input.provider.id === "none") {
    return productModeFailure({
      mode: input.mode,
      provider: input.provider?.id ?? "none",
      errorCode: "MODEL_PROVIDER_REQUIRED",
      message: `${productModeLabel(input.mode)} requires an enabled model provider. Scanner fallback is intentionally not used for this mode.`,
      remediation: "Enable a local or approved remote model provider, or run deep-assisted mode for scanner-backed reporting.",
    });
  }

  const started = Date.now();
  const runtime = await createCodeInspectionRuntime(input.repoRoot);
  try {
    if (input.mode === "single-agent") {
      return await runSingleAgentScan(input, runtime, started);
    }
    if (input.mode === "scanner-moa-assisted") {
      return await runScannerMoaAgentScan(input, runtime, started);
    }
    return await runMoaAgentScan(input, runtime, started);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return productModeFailure({
      mode: input.mode,
      provider: input.provider.id,
      errorCode: "MODEL_PROVIDER_FAILED",
      message: `${productModeLabel(input.mode)} failed safely: ${message}`,
      remediation: "Check the configured model provider and retry, or switch to deep-assisted scanner-backed reporting.",
      durationMs: Date.now() - started,
    });
  }
}

async function runSingleAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
): Promise<ProductAgentScanResult> {
  const snapshot = await runtime.buildSnapshot();
  const modelSelection = await resolveRoleModel(input, "single-agent-inspector");
  const response = await completeWithTimeout(
    modelSelection.provider,
    singleAgentRequest(snapshot),
    modelSelection.providerConfig,
    modelTimeoutMs(modelSelection.providerConfig?.timeoutMs),
  );
  const candidates = await parseFindingCandidates({
    raw: response.content,
    runtime,
    repoRoot: input.repoRoot,
    mode: "single-agent",
    source: "single-agent",
    provider: response.provider,
    model: response.model,
  });
  const findings = dedupeCandidateFindings(candidates.map((candidate) => candidate.finding)).slice(0, productFindingLimit());
  return productModeSuccess({
    mode: "single-agent",
    provider: response.provider,
    model: response.model,
    findings,
    agentMode: buildSingleAgentModeMetadata(response.provider, response.model, findings, Date.now() - started),
    started,
    limitations: [
      "Single-agent code inspection used bounded read-only file, search, and snippet context.",
      findings.length === 0 ? "The model response contained no validated product-mode findings." : "",
    ].filter(Boolean),
  });
}

async function runMoaAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
): Promise<ProductAgentScanResult> {
  const allCandidates: CandidateFinding[] = [];
  let model: string | undefined;
  const agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator";
    provider: string;
    model?: string;
    status: "completed";
  }> = [];

  for (const role of PRODUCT_AGENT_SPECIALISTS) {
    const snapshot = await runtime.buildSnapshot({
      maxFiles: 120,
      maxSearches: role.searchQueries.length,
      maxSearchResults: 36,
      maxSnippets: 10,
      searchQueries: role.searchQueries,
    });
    const modelSelection = await resolveRoleModel(input, role.id as ProductAgentRoleId);
    const response = await completeWithTimeout(
      modelSelection.provider,
      specialistRequest(role, snapshot, "moa-assisted"),
      modelSelection.providerConfig,
      modelTimeoutMs(modelSelection.providerConfig?.timeoutMs),
    );
    model = response.model;
    agentRuns.push({
      id: role.id,
      label: role.label,
      role: "specialist",
      provider: response.provider,
      model: response.model,
      status: "completed",
    });
    const candidates = await parseFindingCandidates({
      raw: response.content,
      runtime,
      repoRoot: input.repoRoot,
      mode: "moa-assisted",
      source: "moa-specialist",
      provider: response.provider,
      model: response.model,
      role: role.id,
    });
    allCandidates.push(...candidates);
  }

  const judgeSelection = await resolveRoleModel(input, "moa-false-positive-judge");
  const judgeResponse = await completeWithTimeout(
    judgeSelection.provider,
    judgeRequest(allCandidates, "moa-assisted"),
    judgeSelection.providerConfig,
    modelTimeoutMs(judgeSelection.providerConfig?.timeoutMs),
  );
  model = judgeResponse.model;
  agentRuns.push({
    id: "moa-false-positive-judge",
    label: "False-positive Judge",
    role: "judge",
    provider: judgeResponse.provider,
    model: judgeResponse.model,
    status: "completed",
  });
  const judgments = parseJudgeResults(judgeResponse.content);
  const judgmentCounts = countJudgments(allCandidates, judgments);
  const judgedCandidates = applyJudgments(allCandidates, judgments, judgeResponse.model);

  const aggregatorSelection = await resolveRoleModel(input, "moa-aggregator");
  const aggregatorResponse = await completeWithTimeout(
    aggregatorSelection.provider,
    aggregatorRequest(judgedCandidates, "moa-assisted"),
    aggregatorSelection.providerConfig,
    modelTimeoutMs(aggregatorSelection.providerConfig?.timeoutMs),
  );
  model = aggregatorResponse.model;
  agentRuns.push({
    id: "moa-aggregator",
    label: "MoA Aggregator",
    role: "aggregator",
    provider: aggregatorResponse.provider,
    model: aggregatorResponse.model,
    status: "completed",
  });
  const aggregated = await parseFindingCandidates({
    raw: aggregatorResponse.content,
    runtime,
    repoRoot: input.repoRoot,
    mode: "moa-assisted",
    source: "moa-aggregator",
    provider: aggregatorResponse.provider,
    model: aggregatorResponse.model,
    candidateIds: judgedCandidates.map((candidate) => candidate.candidateId),
  });

  const fallbackFindings = judgedCandidates.map((candidate) => candidate.finding);
  const finalFindings = dedupeCandidateFindings((aggregated.length > 0 ? aggregated.map((candidate) => candidate.finding) : fallbackFindings))
    .slice(0, productFindingLimit());

  return productModeSuccess({
    mode: "moa-assisted",
    provider: input.provider.id,
    ...(model ? { model } : {}),
    findings: finalFindings,
    agentMode: buildMoaModeMetadata({
      provider: input.provider.id,
      model,
      agentRuns,
      findings: finalFindings,
      candidateCount: allCandidates.length,
      acceptedCount: judgmentCounts.accepted,
      rejectedCount: judgmentCounts.rejected,
      needsReviewCount: judgmentCounts.needsReview,
      runtimeMs: Date.now() - started,
    }),
    started,
    limitations: [
      `MoA ran ${PRODUCT_AGENT_SPECIALISTS.length} specialist role(s), a false-positive judge, and an aggregator.`,
      aggregated.length === 0 && fallbackFindings.length > 0 ? "Aggregator output had no validated findings; judged specialist candidates were retained." : "",
      finalFindings.length === 0 ? "MoA completed but produced no validated product-mode findings." : "",
    ].filter(Boolean),
  });
}

async function runScannerMoaAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
): Promise<ProductAgentScanResult> {
  const scannerCandidates = scannerCandidatesFromFindings(input.scannerFindings ?? [], input.repoRoot);
  const allCandidates: CandidateFinding[] = [...scannerCandidates];
  let model: string | undefined;
  const agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator" | "scanner";
    provider: string;
    model?: string;
    status: "completed" | "failed";
  }> = [];
  const limitations: string[] = [];

  if (scannerCandidates.length > 0) {
    agentRuns.push({
      id: "scanner-stack",
      label: "Scanner Stack",
      role: "scanner",
      provider: "hermsec-scanners",
      status: "completed",
    });
  }

  for (const role of PRODUCT_AGENT_SPECIALISTS) {
    const snapshot = await runtime.buildSnapshot({
      maxFiles: 120,
      maxSearches: role.searchQueries.length,
      maxSearchResults: 36,
      maxSnippets: 10,
      searchQueries: role.searchQueries,
    });
    const modelSelection = await resolveRoleModel(input, role.id as ProductAgentRoleId);
    let response: Awaited<ReturnType<ModelProviderAdapter["complete"]>>;
    try {
      response = await completeWithTimeout(
        modelSelection.provider,
        specialistRequest(role, snapshot, "scanner-moa-assisted"),
        modelSelection.providerConfig,
        modelTimeoutMs(modelSelection.providerConfig?.timeoutMs),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      limitations.push(`${role.label} failed safely: ${message}`);
      agentRuns.push({
        id: role.id,
        label: role.label,
        role: "specialist",
        provider: modelSelection.provider.id,
        ...(modelSelection.providerConfig?.model ? { model: modelSelection.providerConfig.model } : {}),
        status: "failed",
      });
      continue;
    }
    model = response.model;
    agentRuns.push({
      id: role.id,
      label: role.label,
      role: "specialist",
      provider: response.provider,
      model: response.model,
      status: "completed",
    });
    const candidates = await parseFindingCandidates({
      raw: response.content,
      runtime,
      repoRoot: input.repoRoot,
      mode: "scanner-moa-assisted",
      source: "moa-specialist",
      provider: response.provider,
      model: response.model,
      role: role.id,
    });
    allCandidates.push(...candidates);
  }

  if (allCandidates.length === 0) {
    return productModeSuccess({
      mode: "scanner-moa-assisted",
      provider: input.provider.id,
      ...(model ? { model } : {}),
      findings: [],
      agentMode: buildScannerMoaModeMetadata({
        provider: input.provider.id,
        model,
        agentRuns,
        findings: [],
        scannerCandidateCount: 0,
        agentCandidateCount: 0,
        acceptedCount: 0,
        rejectedCount: 0,
        needsReviewCount: 0,
        runtimeMs: Date.now() - started,
      }),
      started,
      limitations: ["Scanner + MoA completed but produced no candidate findings to judge."],
    });
  }

  const judgeSelection = await resolveRoleModel(input, "moa-false-positive-judge");
  const judgeResponse = await completeRoleWithTimeout(
    "false-positive judge",
    judgeSelection.provider,
    judgeRequest(allCandidates, "scanner-moa-assisted"),
    judgeSelection.providerConfig,
  );
  model = judgeResponse.model;
  agentRuns.push({
    id: "moa-false-positive-judge",
    label: "False-positive Judge",
    role: "judge",
    provider: judgeResponse.provider,
    model: judgeResponse.model,
    status: "completed",
  });
  const judgments = parseJudgeResults(judgeResponse.content);
  const judgmentCounts = countJudgments(allCandidates, judgments);
  const judgedCandidates = applyJudgments(allCandidates, judgments, judgeResponse.model);

  const aggregatorSelection = await resolveRoleModel(input, "moa-aggregator");
  const aggregatorResponse = await completeRoleWithTimeout(
    "final aggregator",
    aggregatorSelection.provider,
    aggregatorRequest(judgedCandidates, "scanner-moa-assisted"),
    aggregatorSelection.providerConfig,
  );
  model = aggregatorResponse.model;
  agentRuns.push({
    id: "moa-aggregator",
    label: "Scanner + MoA Aggregator",
    role: "aggregator",
    provider: aggregatorResponse.provider,
    model: aggregatorResponse.model,
    status: "completed",
  });
  const aggregated = await parseFindingCandidates({
    raw: aggregatorResponse.content,
    runtime,
    repoRoot: input.repoRoot,
    mode: "scanner-moa-assisted",
    source: "moa-aggregator",
    provider: aggregatorResponse.provider,
    model: aggregatorResponse.model,
    candidateIds: judgedCandidates.map((candidate) => candidate.candidateId),
  });

  const finalFindings = finalizeScannerMoaFindings(aggregated, judgedCandidates)
    .slice(0, productFindingLimit());

  return productModeSuccess({
    mode: "scanner-moa-assisted",
    provider: input.provider.id,
    ...(model ? { model } : {}),
    findings: finalFindings,
    agentMode: buildScannerMoaModeMetadata({
      provider: input.provider.id,
      model,
      agentRuns,
      findings: finalFindings,
      scannerCandidateCount: scannerCandidates.length,
      agentCandidateCount: allCandidates.length - scannerCandidates.length,
      acceptedCount: judgmentCounts.accepted,
      rejectedCount: judgmentCounts.rejected,
      needsReviewCount: judgmentCounts.needsReview,
      runtimeMs: Date.now() - started,
    }),
    started,
    limitations: [
      ...limitations,
      `Scanner + MoA judged ${allCandidates.length} combined scanner and agent candidate finding${allCandidates.length === 1 ? "" : "s"}.`,
      aggregated.length === 0 && judgedCandidates.length > 0 ? "Aggregator output had no validated findings; judged candidates were retained." : "",
      finalFindings.length === 0 ? "The false-positive judge and aggregator rejected all candidate findings." : "",
    ].filter(Boolean),
  });
}

function scannerCandidatesFromFindings(findings: readonly Finding[], repoRoot: string): CandidateFinding[] {
  const generatedAt = new Date().toISOString();
  return [...findings]
    .sort(compareAgentFindings)
    .slice(0, scannerCandidateLimit())
    .map((finding) => {
      const candidateId = `scanner:${finding.id}`;
      return {
        candidateId,
        finding: normalizeFinding({
          ...finding,
          agent: {
            mode: "scanner-moa-assisted",
            source: "scanner-backed",
            provider: "hermsec-scanners",
            ...(finding.tool ? { role: finding.tool } : {}),
            generatedAt,
            candidateIds: [candidateId],
            sourceFindingIds: [finding.id],
          },
        }, repoRoot),
      };
    });
}

function finalizeScannerMoaFindings(
  aggregated: readonly CandidateFinding[],
  judgedCandidates: readonly CandidateFinding[],
): Finding[] {
  if (aggregated.length === 0) {
    return dedupeCandidateFindings(judgedCandidates.map((candidate) => candidate.finding));
  }
  const referenced = new Set(
    aggregated.flatMap((candidate) => candidate.finding.agent?.sourceFindingIds ?? []),
  );
  const retainedScannerFindings = judgedCandidates
    .filter((candidate) => candidate.finding.agent?.source === "scanner-backed")
    .filter((candidate) => !referenced.has(candidate.candidateId))
    .map((candidate) => candidate.finding);
  return dedupeCandidateFindings([
    ...aggregated.map((candidate) => candidate.finding),
    ...retainedScannerFindings,
  ]);
}

async function resolveRoleModel(
  input: ProductAgentScanInput,
  roleId: ProductAgentRoleId,
): Promise<ProductAgentModelSelection> {
  const selected = await input.modelResolver?.(roleId);
  return selected ?? {
    provider: input.provider,
    ...(input.providerConfig ? { providerConfig: input.providerConfig } : {}),
  };
}

function singleAgentRequest(snapshot: CodeInspectionSnapshot): ModelRequest {
  return jsonRequest([
    "You are Hermsec single-agent product security inspection.",
    "You receive bounded output from list_files, search_code, and read_file_snippet helpers. You cannot request shell commands, package execution, installs, or network access.",
    "This is an agent-only scan. Use only the supplied repository evidence.",
    "Return ONLY one JSON object with a findings array.",
    findingSchemaInstruction(),
    "Only report concrete defensive findings supported by the supplied file paths and snippets. Prefer no finding over speculation.",
    "Context:",
    JSON.stringify(redactForModel({
      inspection: snapshot,
    }).value),
  ].join("\n"));
}

function specialistRequest(role: SpecialistRole, snapshot: CodeInspectionSnapshot, mode: ProductAgentScanMode): ModelRequest {
  return jsonRequest([
    `You are the Hermsec MoA specialist: ${role.label}.`,
    role.focus,
    "You receive bounded output from list_files, search_code, and read_file_snippet helpers. You cannot request shell commands, package execution, installs, or network access.",
    mode === "scanner-moa-assisted"
      ? "This is a scanner + MoA hybrid scan. Inspect the supplied repository evidence independently; scanner findings will be judged together with your candidates later."
      : "This is an agent-only scan. Use only the supplied repository evidence.",
    "Return ONLY one JSON object with a findings array.",
    findingSchemaInstruction(),
    "Report only findings supported by supplied snippets and file paths. If unsure, return an empty findings array.",
    "Context:",
    JSON.stringify(redactForModel({
      inspection: snapshot,
    }).value),
  ].join("\n"));
}

function judgeRequest(candidates: readonly CandidateFinding[], mode: ProductAgentScanMode): ModelRequest {
  return jsonRequest([
    "You are the Hermsec MoA false-positive judge.",
    mode === "scanner-moa-assisted"
      ? "Review scanner-backed and MoA specialist candidates together. Accept candidates with concrete evidence, mark uncertain but plausible items as needs-review, and reject weak scanner noise or unsupported model claims."
      : "Review candidate findings for support in their own evidence only. Reject speculation, unsupported files, impossible line references, or vague best-practice advice.",
    "Return ONLY JSON: {\"judgments\":[{\"candidateId\":\"...\",\"verdict\":\"accepted|rejected|needs-review\",\"confidence\":\"low|medium|high\",\"reason\":\"short reason\"}]}",
    "Candidates:",
    JSON.stringify(redactForModel(candidates.map((candidate) => ({
      candidateId: candidate.candidateId,
      source: candidate.finding.agent?.source,
      tool: candidate.finding.tool,
      ruleId: candidate.finding.ruleId,
      cwe: candidate.finding.cwe,
      title: candidate.finding.title,
      severity: candidate.finding.severity,
      category: candidate.finding.category,
      location: candidate.finding.location,
      evidence: candidate.finding.evidence,
      remediation: candidate.finding.remediation,
      role: candidate.finding.agent?.role,
    }))).value),
  ].join("\n"));
}

function aggregatorRequest(candidates: readonly CandidateFinding[], mode: ProductAgentScanMode): ModelRequest {
  return jsonRequest([
    mode === "scanner-moa-assisted" ? "You are the Hermsec scanner + MoA final aggregator." : "You are the Hermsec MoA aggregator.",
    "Deduplicate accepted and needs-review candidates into the smallest useful set of final defensive findings.",
    "Return ONLY one JSON object with a findings array.",
    findingSchemaInstruction(),
    mode === "scanner-moa-assisted"
      ? "Prefer candidates where scanner evidence and MoA evidence agree. Keep scanner-only findings only when evidence is concrete. Do not invent new files, lines, identifiers, packages, CVEs, CWEs, scanners, or candidate IDs. Preserve candidate IDs in sourceFindingIds."
      : "Do not invent new files, lines, identifiers, packages, or scanners. Preserve candidate IDs in sourceFindingIds when relevant.",
    "Candidates:",
    JSON.stringify(redactForModel(candidates.map((candidate) => ({
      candidateId: candidate.candidateId,
      source: candidate.finding.agent?.source,
      tool: candidate.finding.tool,
      ruleId: candidate.finding.ruleId,
      cwe: candidate.finding.cwe,
      title: candidate.finding.title,
      severity: candidate.finding.severity,
      category: candidate.finding.category,
      confidence: candidate.finding.confidence,
      location: candidate.finding.location,
      evidence: candidate.finding.evidence,
      remediation: candidate.finding.remediation,
      judge: candidate.finding.agent?.judge,
    }))).value),
  ].join("\n"));
}

function jsonRequest(content: string): ModelRequest {
  return {
    messages: [
      { role: "system", content: hermsecSystemPrompt },
      { role: "user", content },
    ],
    temperature: 0,
    maxTokens: 4_000,
    responseFormat: "json",
  };
}

function findingSchemaInstruction(): string {
  return [
    "Finding JSON schema:",
    "{\"findings\":[{\"title\":\"short title\",\"category\":\"code|dependency|secret|supply-chain|config\",\"severity\":\"critical|high|medium|low|info\",\"confidence\":\"low|medium|high\",\"description\":\"defensive description\",\"evidence\":\"quote or paraphrase from supplied snippet\",\"remediation\":\"safe defensive fix\",\"ruleId\":\"stable rule id\",\"cwe\":[\"CWE-...\"],\"location\":{\"file\":\"repo-relative path\",\"startLine\":1,\"endLine\":1},\"sourceFindingIds\":[\"optional candidate ids\"]}]}",
    "Never use confidence=confirmed for model-only findings.",
  ].join("\n");
}

async function parseFindingCandidates(input: {
  raw: string;
  runtime: CodeInspectionRuntime;
  repoRoot: string;
  mode: ProductAgentScanMode;
  source: AgentFindingMetadata["source"];
  provider: string;
  model?: string;
  role?: string;
  candidateIds?: string[];
}): Promise<CandidateFinding[]> {
  const object = parseJsonObject(input.raw);
  const rawFindings = Array.isArray(object?.findings) ? object.findings : [];
  const result: CandidateFinding[] = [];
  for (const rawFinding of rawFindings.slice(0, productCandidateLimit())) {
    if (!isRecord(rawFinding)) {
      continue;
    }
    const candidate = await toFindingCandidate(rawFinding, input);
    if (candidate) {
      result.push(candidate);
    }
  }
  return result;
}

async function toFindingCandidate(
  raw: RawAgentFinding,
  context: {
    runtime: CodeInspectionRuntime;
    repoRoot: string;
    mode: ProductAgentScanMode;
    source: AgentFindingMetadata["source"];
    provider: string;
    model?: string;
    role?: string;
    candidateIds?: string[];
  },
): Promise<CandidateFinding | undefined> {
  const title = stringValue(raw.title, 180);
  const evidence = stringValue(raw.evidence, 900);
  const remediation = stringValue(raw.remediation, 900);
  const location = locationValue(raw.location);
  if (!title || !evidence || !remediation || !location?.file) {
    return undefined;
  }

  try {
    const snippet = await context.runtime.readFileSnippet({
      path: location.file,
      startLine: location.startLine ?? 1,
      endLine: location.endLine ?? location.startLine ?? 1,
      contextLines: 0,
      maxChars: 2_000,
    });
    if (location.startLine !== undefined && snippet.startLine !== location.startLine) {
      return undefined;
    }
    location.file = snippet.file;
  } catch {
    return undefined;
  }

  const sourceFindingIds = stringArray(raw.sourceFindingIds, 12);
  const candidateId = stringValue(raw.candidateId, 120) ?? stableId(JSON.stringify({
    title,
    location,
    evidence,
    role: context.role,
  }), "candidate");
  const sourceFindingMetadata = sourceFindingIds.length > 0
    ? sourceFindingIds
    : context.candidateIds && context.candidateIds.length > 0
      ? context.candidateIds
      : [];
  const agent: AgentFindingMetadata = {
    mode: context.mode,
    source: context.source,
    provider: context.provider,
    ...(context.model ? { model: context.model } : {}),
    ...(context.role ? { role: context.role } : {}),
    generatedAt: new Date().toISOString(),
    candidateIds: [candidateId],
    ...(sourceFindingMetadata.length > 0 ? { sourceFindingIds: sourceFindingMetadata } : {}),
    ...(context.source === "moa-aggregator"
      ? {
          judge: {
            verdict: "accepted",
            reviewedBy: "moa-false-positive-judge",
            reason: "Aggregated from MoA candidates that passed false-positive judging.",
          },
        }
      : {}),
  };
  const finding: Finding = normalizeFinding({
    id: stableId(`${context.mode}:${context.source}:${candidateId}`, "finding"),
    title,
    category: categoryValue(raw.category),
    severity: severityValue(raw.severity),
    confidence: confidenceValue(raw.confidence, context.source),
    description: stringValue(raw.description, 900) ?? title,
    evidence,
    remediation,
    tool: toolForAgentFinding(context.mode),
    ruleId: stringValue(raw.ruleId, 120) ?? `hermsec.agent.${context.source}`,
    cwe: cweArray(raw.cwe),
    location,
    agent,
    fingerprint: stableId(JSON.stringify({
      mode: context.mode,
      source: context.source,
      title,
      location,
      cwe: cweArray(raw.cwe),
    }), "fp"),
  }, context.repoRoot);

  return { candidateId, finding };
}

function parseJudgeResults(raw: string): JudgeResult[] {
  const object = parseJsonObject(raw);
  const judgments = Array.isArray(object?.judgments) ? object.judgments : [];
  return judgments.flatMap((item) => {
    if (!isRecord(item)) {
      return [];
    }
    const candidateId = stringValue(item.candidateId, 120);
    if (!candidateId) {
      return [];
    }
    const verdict = item.verdict === "accepted" || item.verdict === "rejected" || item.verdict === "needs-review"
      ? item.verdict
      : "needs-review";
    const confidence = item.confidence === "low" || item.confidence === "medium" || item.confidence === "high"
      ? item.confidence
      : undefined;
    const reason = stringValue(item.reason, 360);
    return [{
      candidateId,
      verdict,
      ...(confidence ? { confidence } : {}),
      ...(reason ? { reason } : {}),
    }];
  });
}

function applyJudgments(candidates: readonly CandidateFinding[], judgments: readonly JudgeResult[], model: string): CandidateFinding[] {
  const byId = new Map(judgments.map((judgment) => [judgment.candidateId, judgment]));
  return candidates.flatMap((candidate) => {
    const judgment = byId.get(candidate.candidateId) ?? {
      candidateId: candidate.candidateId,
      verdict: "needs-review" as const,
      confidence: "low" as const,
      reason: "No explicit judge decision was returned.",
    };
    if (judgment.verdict === "rejected") {
      return [];
    }
    return [{
      candidateId: candidate.candidateId,
      finding: {
        ...candidate.finding,
        confidence: judgment.verdict === "accepted" && judgment.confidence === "high" ? "high" : candidate.finding.confidence,
        agent: {
          ...candidate.finding.agent!,
          model: candidate.finding.agent?.model ?? model,
          judge: {
            verdict: judgment.verdict,
            ...(judgment.confidence ? { confidence: judgment.confidence } : {}),
            ...(judgment.reason ? { reason: judgment.reason } : {}),
            reviewedBy: "moa-false-positive-judge",
          },
        },
      },
    }];
  });
}

function productModeSuccess(input: {
  mode: ProductAgentScanMode;
  provider: string;
  model?: string;
  findings: Finding[];
  agentMode: ReportAgentModeMetadata;
  started: number;
  limitations: string[];
}): ProductAgentScanResult {
  const status: ScannerStatus = {
    id: input.mode,
    label: productModeLabel(input.mode),
    status: "completed",
    message: `${productModeLabel(input.mode)} completed with ${input.findings.length} validated finding${input.findings.length === 1 ? "" : "s"}.`,
    durationMs: Date.now() - input.started,
  };
  return {
    ok: true,
    findings: input.findings,
    status,
    provider: input.provider,
    ...(input.model ? { model: input.model } : {}),
    limitations: input.limitations,
    executiveSummary: `${productModeLabel(input.mode)} produced ${input.findings.length} validated ${input.mode === "scanner-moa-assisted" ? "scanner and agent" : "agent-only"} finding${input.findings.length === 1 ? "" : "s"}.`,
    priorityActions: input.findings.slice(0, 5).map((finding) => `${finding.id}: ${finding.remediation}`),
    agentMode: input.agentMode,
  };
}

function productModeFailure(input: {
  mode: ProductAgentScanMode;
  provider: string;
  errorCode: ProductAgentScanResult extends infer Result ? Result extends { ok: false; errorCode: infer Code } ? Code : never : never;
  message: string;
  remediation: string;
  durationMs?: number;
}): ProductAgentScanResult {
  return {
    ok: false,
    findings: [],
    status: {
      id: input.mode,
      label: productModeLabel(input.mode),
      status: "failed",
      message: input.message,
      ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
    },
    provider: input.provider,
    errorCode: input.errorCode,
    message: input.message,
    remediation: input.remediation,
    limitations: [input.message],
  };
}

function productModeLabel(mode: ProductAgentScanMode): string {
  if (mode === "single-agent") return "Single-agent inspection";
  if (mode === "scanner-moa-assisted") return "Scanner + MoA inspection";
  return "MoA-assisted inspection";
}

function toolForAgentFinding(mode: ProductAgentScanMode): string {
  if (mode === "single-agent") return "hermsec-agent";
  if (mode === "scanner-moa-assisted") return "hermsec-scanner-moa";
  return "hermsec-moa";
}

function buildSingleAgentModeMetadata(
  provider: string,
  model: string,
  findings: readonly Finding[],
  runtimeMs: number,
): ReportAgentModeMetadata {
  return {
    mode: "single-agent",
    scanMode: "single-agent",
    modeLabel: productModeLabel("single-agent"),
    agentsUsed: ["single-agent-inspector"],
    agents: [
      {
        id: "single-agent-inspector",
        label: "Single Agent Inspector",
        role: "security-inspector",
        provider,
        model,
        runtimeMs,
        status: "completed",
      },
    ],
    candidateFindingCount: findings.length,
    acceptedFindingCount: findings.length,
    rejectedFindingCount: 0,
    needsHumanReviewCount: 0,
    totalAgentRuntimeMs: runtimeMs,
    findings: findingMetadataMap(findings),
  };
}

function buildMoaModeMetadata(input: {
  provider: string;
  model?: string | undefined;
  agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator";
    provider: string;
    model?: string;
    status: "completed";
  }>;
  findings: readonly Finding[];
  candidateCount: number;
  acceptedCount: number;
  rejectedCount: number;
  needsReviewCount: number;
  runtimeMs: number;
}): ReportAgentModeMetadata {
  return {
    mode: "moa-assisted",
    scanMode: "moa-assisted",
    modeLabel: productModeLabel("moa-assisted"),
    agentsUsed: [
      ...PRODUCT_AGENT_SPECIALISTS.map((role) => role.id),
      "moa-false-positive-judge",
      "moa-aggregator",
    ],
    agents: [
      ...input.agentRuns,
    ],
    candidateFindingCount: input.candidateCount,
    acceptedFindingCount: input.acceptedCount,
    rejectedFindingCount: input.rejectedCount,
    needsHumanReviewCount: input.needsReviewCount,
    ...(input.model ? { aggregatorModel: input.model } : {}),
    aggregator: {
      agentId: "moa-aggregator",
      provider: input.agentRuns.find((agent) => agent.id === "moa-aggregator")?.provider ?? input.provider,
      ...(input.model ? { model: input.model } : {}),
      label: "MoA Aggregator",
    },
    totalAgentRuntimeMs: input.runtimeMs,
    findings: findingMetadataMap(input.findings),
  };
}

function buildScannerMoaModeMetadata(input: {
  provider: string;
  model?: string | undefined;
  agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator" | "scanner";
    provider: string;
    model?: string;
    status: "completed" | "failed";
  }>;
  findings: readonly Finding[];
  scannerCandidateCount: number;
  agentCandidateCount: number;
  acceptedCount: number;
  rejectedCount: number;
  needsReviewCount: number;
  runtimeMs: number;
}): ReportAgentModeMetadata {
  return {
    mode: "scanner-moa-assisted",
    scanMode: "scanner-moa-assisted",
    modeLabel: productModeLabel("scanner-moa-assisted"),
    agentsUsed: [
      "scanner-stack",
      ...PRODUCT_AGENT_SPECIALISTS.map((role) => role.id),
      "moa-false-positive-judge",
      "moa-aggregator",
    ],
    agents: [
      ...input.agentRuns,
    ],
    candidateFindingCount: input.scannerCandidateCount + input.agentCandidateCount,
    acceptedFindingCount: input.acceptedCount,
    rejectedFindingCount: input.rejectedCount,
    needsHumanReviewCount: input.needsReviewCount,
    ...(input.model ? { aggregatorModel: input.model } : {}),
    aggregator: {
      agentId: "moa-aggregator",
      provider: input.agentRuns.find((agent) => agent.id === "moa-aggregator")?.provider ?? input.provider,
      ...(input.model ? { model: input.model } : {}),
      label: "Scanner + MoA Aggregator",
    },
    totalAgentRuntimeMs: input.runtimeMs,
    findings: findingMetadataMap(input.findings),
  };
}

function findingMetadataMap(findings: readonly Finding[]): NonNullable<ReportAgentModeMetadata["findings"]> {
  const mapped: NonNullable<ReportAgentModeMetadata["findings"]> = {};
  for (const finding of findings) {
    const sourceLabel = sourceLabelForFinding(finding);
    mapped[finding.id] = {
      sourceLabel,
      sourceLabels: [sourceLabel],
      ...(finding.agent?.judge?.verdict ? { judgeStatus: finding.agent.judge.verdict } : {}),
      ...(finding.agent?.judge?.reason ? { judgeReason: finding.agent.judge.reason } : {}),
      agentIds: [finding.agent?.role ?? finding.agent?.source ?? "agent"].filter(Boolean),
    };
  }
  return mapped;
}

function sourceLabelForFinding(finding: Finding): ReportFindingSourceLabel {
  if (finding.agent?.source === "single-agent") return "single-agent-inspected";
  if (finding.agent?.source === "moa-specialist") return "moa-specialist";
  if (finding.agent?.source === "moa-aggregator") return "moa-aggregated";
  return "scanner-backed";
}

function countJudgments(candidates: readonly CandidateFinding[], judgments: readonly JudgeResult[]): {
  accepted: number;
  rejected: number;
  needsReview: number;
} {
  const byId = new Map(judgments.map((judgment) => [judgment.candidateId, judgment]));
  let accepted = 0;
  let rejected = 0;
  let needsReview = 0;
  for (const candidate of candidates) {
    const verdict = byId.get(candidate.candidateId)?.verdict ?? "needs-review";
    if (verdict === "accepted") accepted += 1;
    else if (verdict === "rejected") rejected += 1;
    else needsReview += 1;
  }
  return { accepted, rejected, needsReview };
}

function dedupeCandidateFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.fingerprint)) {
      continue;
    }
    seen.add(finding.fingerprint);
    result.push(finding);
  }
  return result.sort(compareAgentFindings);
}

function compareAgentFindings(left: Finding, right: Finding): number {
  const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (
    severityRank[left.severity] - severityRank[right.severity] ||
    (left.location?.file ?? "").localeCompare(right.location?.file ?? "") ||
    (left.location?.startLine ?? 0) - (right.location?.startLine ?? 0) ||
    left.title.localeCompare(right.title)
  );
}

async function completeWithTimeout(
  provider: ModelProviderAdapter,
  request: ModelRequest,
  config: ProviderConfig | undefined,
  timeoutMs: number,
): ReturnType<ModelProviderAdapter["complete"]> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      provider.complete(request, config),
      new Promise<Awaited<ReturnType<ModelProviderAdapter["complete"]>>>((_, reject) => {
        timer = setTimeout(() => reject(new Error("product-agent-model-watchdog")), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

async function completeRoleWithTimeout(
  roleLabel: string,
  provider: ModelProviderAdapter,
  request: ModelRequest,
  config: ProviderConfig | undefined,
): ReturnType<ModelProviderAdapter["complete"]> {
  try {
    return await completeWithTimeout(
      provider,
      request,
      config,
      modelTimeoutMs(config?.timeoutMs),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${roleLabel} failed: ${message}`);
  }
}

function modelTimeoutMs(configuredTimeoutMs: number | undefined): number {
  return Math.min(configuredTimeoutMs ?? 45_000, 90_000);
}

function productFindingLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_FINDING_LIMIT", 40, 1, 200);
}

function productCandidateLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT", 80, 1, 300);
}

function scannerCandidateLimit(): number {
  return boundedEnvInt("HERMSEC_SCANNER_MOA_SCANNER_CANDIDATE_LIMIT", 120, 1, 500);
}

function boundedEnvInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

function parseJsonObject(raw: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    const match = raw.match(/\{[\s\S]*\}/u);
    if (!match) {
      return undefined;
    }
    try {
      const parsed = JSON.parse(match[0]) as unknown;
      return isRecord(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.replace(/\s+/g, " ").trim();
  if (!trimmed) {
    return undefined;
  }
  return trimmed.length > max ? `${trimmed.slice(0, max - 3)}...` : trimmed;
}

function stringArray(value: unknown, maxItems: number): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .flatMap((item) => {
      const normalized = stringValue(item, 120);
      return normalized ? [normalized] : [];
    })
    .slice(0, maxItems);
}

function categoryValue(value: unknown): FindingCategory {
  return typeof value === "string" && categoryValues.has(value as FindingCategory) ? value as FindingCategory : "code";
}

function severityValue(value: unknown): Severity {
  return typeof value === "string" && severityValues.has(value as Severity) ? value as Severity : "medium";
}

function confidenceValue(value: unknown, source: AgentFindingMetadata["source"]): Finding["confidence"] {
  if (typeof value !== "string" || !confidenceValues.has(value as Finding["confidence"])) {
    return "medium";
  }
  if (value === "confirmed") {
    return "high";
  }
  if (source !== "moa-aggregator" && value === "high") {
    return "medium";
  }
  return value as Finding["confidence"];
}

function cweArray(value: unknown): string[] {
  return stringArray(value, 8)
    .map((item) => item.toUpperCase())
    .filter((item) => /^CWE-\d{1,6}$/u.test(item));
}

function locationValue(value: unknown): Finding["location"] | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const file = stringValue(value.file, 300);
  if (!file) {
    return undefined;
  }
  const startLine = lineValue(value.startLine);
  const endLine = lineValue(value.endLine);
  return {
    file,
    ...(startLine !== undefined ? { startLine } : {}),
    ...(endLine !== undefined && startLine !== undefined && endLine >= startLine ? { endLine } : {}),
  };
}

function lineValue(value: unknown): number | undefined {
  const numberValue = typeof value === "number" ? value : typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;
  if (!Number.isInteger(numberValue) || numberValue < 1 || numberValue > 5_000_000) {
    return undefined;
  }
  return numberValue;
}
