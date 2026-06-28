import {
  buildInvestigationTasks,
  candidatePromptContext,
  discoverInvestigationCandidates,
  type InvestigationTask,
} from "./candidateDiscovery.js";
import { createCodeInspectionRuntime, type CodeInspectionRuntime } from "./codeInspection.js";
import { revalidateProductFindingEvidence, type EvidenceSourceCandidate } from "./evidenceRevalidation.js";
import {
  createProductAgentCheckpointStore,
  createProductAgentScanCheckpoint,
  type ProductAgentCheckpointStore,
  type ProductAgentScanCheckpoint,
} from "./productScanCheckpoint.js";
import { emitProductAgentProgress } from "./productScanProgress.js";
import { redactForModel } from "./redaction.js";
import { hermsecSystemPrompt } from "./systemPrompt.js";
import type { ScanProgressCallback } from "../core/progress.js";
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
  | "database-and-storage"
  | "config-and-iac"
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
  reportOutputDirectory?: string;
  onProgress?: ScanProgressCallback;
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

type ProductAgentRunState = {
  onProgress?: ScanProgressCallback;
  checkpointStore?: ProductAgentCheckpointStore;
  checkpoint?: ProductAgentScanCheckpoint;
  checkpointResumed: boolean;
  checkpointPath?: string;
};

type JudgeVerdict = "accepted" | "rejected";

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
  {
    id: "database-and-storage",
    label: "Database and storage specialist",
    focus: "Find unsafe database access, direct object storage exposure, weak persistence controls, unsafe migrations, and data retention risks.",
    searchQueries: ["query(", "execute(", "raw(", "whereRaw", "findOne", "ObjectId", "mongoose", "sequelize", "typeorm", "s3", "bucket", "storage"],
  },
  {
    id: "config-and-iac",
    label: "Config and IaC specialist",
    focus: "Find risky Docker, Kubernetes, CI, Terraform, cloud, environment, and deployment configuration issues.",
    searchQueries: ["Dockerfile", "docker-compose", "kubernetes", "terraform", "privileged", "0.0.0.0", "CORS", "workflow", "permissions:", "securityContext"],
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
  const runState = await initializeProductAgentRunState(input);
  try {
    if (input.mode === "single-agent") {
      return await runSingleAgentScan(input, runtime, started, runState);
    }
    if (input.mode === "scanner-moa-assisted") {
      return await runScannerMoaAgentScan(input, runtime, started, runState);
    }
    return await runMoaAgentScan(input, runtime, started, runState);
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

async function initializeProductAgentRunState(input: ProductAgentScanInput): Promise<ProductAgentRunState> {
  const state: ProductAgentRunState = {
    ...(input.onProgress ? { onProgress: input.onProgress } : {}),
    checkpointResumed: false,
  };
  if (!input.reportOutputDirectory) {
    return state;
  }
  const checkpointStore = createProductAgentCheckpointStore({
    reportOutputDirectory: input.reportOutputDirectory,
    target: input.repoRoot,
    assistMode: input.mode,
  });
  state.checkpointStore = checkpointStore;
  state.checkpointPath = checkpointStore.location.checkpointPath;
  try {
    const read = await checkpointStore.read();
    state.checkpointResumed = read.resume.available;
    state.checkpoint = read.checkpoint ?? createProductAgentScanCheckpoint({
      reportOutputDirectory: input.reportOutputDirectory,
      target: input.repoRoot,
      assistMode: input.mode,
      currentPhase: "checkpoint",
      metadata: {
        checkpointResumed: read.resume.available,
      },
    });
    emitProductAgentProgress(input.onProgress, {
      phase: "checkpoint",
      assistMode: input.mode,
      status: read.resume.available ? "completed" : "skipped",
      id: "product-agent-checkpoint",
      message: read.resume.available
        ? "Resuming from a compatible product-agent checkpoint."
        : "No compatible product-agent checkpoint was found.",
      checkpointPath: checkpointStore.location.checkpointPath,
      resume: read.resume,
    });
    if (!read.resume.available && state.checkpoint) {
      await checkpointStore.write(state.checkpoint);
    }
  } catch (error) {
    emitProductAgentProgress(input.onProgress, {
      phase: "checkpoint",
      assistMode: input.mode,
      status: "failed",
      id: "product-agent-checkpoint",
      message: `Checkpoint setup failed safely: ${shortError(error instanceof Error ? error.message : String(error))}.`,
      checkpointPath: checkpointStore.location.checkpointPath,
    });
  }
  return state;
}

async function saveProductAgentCheckpoint(
  runState: ProductAgentRunState,
  input: {
    phase: NonNullable<ProductAgentScanCheckpoint["currentPhase"]>;
    tasks?: ProductAgentScanCheckpoint["tasks"];
    candidates?: ProductAgentScanCheckpoint["candidates"];
    finalFindingIds?: string[];
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  if (!runState.checkpointStore || !runState.checkpoint) {
    return;
  }
  try {
    runState.checkpoint = {
      ...runState.checkpoint,
      currentPhase: input.phase,
      ...(input.tasks ? { tasks: input.tasks } : {}),
      ...(input.candidates ? { candidates: input.candidates } : {}),
      ...(input.finalFindingIds ? { finalFindingIds: input.finalFindingIds } : {}),
      metadata: {
        ...(runState.checkpoint.metadata ?? {}),
        checkpointResumed: runState.checkpointResumed,
        ...(input.metadata ?? {}),
      },
    };
    await runState.checkpointStore.write(runState.checkpoint);
  } catch {
    // Checkpoints are best-effort and must not affect scan correctness.
  }
}

function emitCandidateProgress(
  runState: ProductAgentRunState,
  mode: ProductAgentScanMode,
  status: "running" | "completed" | "skipped" | "failed",
  message: string,
  candidateCount?: number,
): void {
  emitProductAgentProgress(runState.onProgress, {
    phase: "candidate",
    assistMode: mode,
    status,
    id: "product-agent-candidate-discovery",
    message,
    ...(candidateCount !== undefined ? { candidateCount } : {}),
    ...(runState.checkpointPath ? { checkpointPath: runState.checkpointPath } : {}),
  });
}

function emitTaskProgress(
  runState: ProductAgentRunState,
  mode: ProductAgentScanMode,
  status: "running" | "completed" | "skipped" | "failed",
  message: string,
  taskCount?: number,
  roleId?: string,
): void {
  emitProductAgentProgress(runState.onProgress, {
    phase: "task",
    assistMode: mode,
    status,
    id: roleId ? `product-agent-task:${roleId}` : "product-agent-focused-tasks",
    message,
    ...(taskCount !== undefined ? { completedCount: taskCount } : {}),
    ...(roleId ? { roleId } : {}),
    ...(runState.checkpointPath ? { checkpointPath: runState.checkpointPath } : {}),
  });
}

function emitRevalidationProgress(
  runState: ProductAgentRunState,
  mode: ProductAgentScanMode,
  status: "running" | "completed" | "skipped" | "failed",
  message: string,
  acceptedCount?: number,
  rejectedCount?: number,
): void {
  emitProductAgentProgress(runState.onProgress, {
    phase: "revalidation",
    assistMode: mode,
    status,
    id: "product-agent-evidence-revalidation",
    message,
    ...(acceptedCount !== undefined ? { acceptedCount } : {}),
    ...(rejectedCount !== undefined ? { rejectedCount } : {}),
    ...(runState.checkpointPath ? { checkpointPath: runState.checkpointPath } : {}),
  });
}

async function runSingleAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
  runState: ProductAgentRunState,
): Promise<ProductAgentScanResult> {
  emitCandidateProgress(runState, "single-agent", "running", "Collecting deterministic investigation candidates.");
  const discovered = await discoverInvestigationCandidates(runtime, {
    maxCandidates: productDiscoveryLimit(),
  });
  emitCandidateProgress(runState, "single-agent", "completed", `Collected ${discovered.length} investigation candidate${discovered.length === 1 ? "" : "s"}.`, discovered.length);
  const tasks = buildInvestigationTasks(discovered, {
    maxTasks: productFocusedTaskLimit(),
  });
  emitTaskProgress(runState, "single-agent", tasks.length > 0 ? "completed" : "skipped", `Prepared ${tasks.length} focused single-agent task${tasks.length === 1 ? "" : "s"}.`, tasks.length);
  await saveProductAgentCheckpoint(runState, {
    phase: "task",
    tasks: checkpointTasksFromInvestigationTasks(tasks, "single-agent-inspector", "completed"),
    candidates: checkpointCandidatesFromInvestigationTasks(tasks, "single-agent", "pending"),
    metadata: {
      candidateCount: discovered.length,
      focusedTaskCount: tasks.length,
    },
  });
  if (tasks.length === 0) {
    return productModeSuccess({
      mode: "single-agent",
      provider: input.provider.id,
      findings: [],
      agentMode: buildSingleAgentModeMetadata(
        input.provider.id,
        input.providerConfig?.model ?? input.provider.id,
        [],
        Date.now() - started,
        { candidateCount: discovered.length, focusedTaskCount: 0, rejectedByRevalidationCount: 0 },
      ),
      runState,
      started,
      limitations: ["Single-agent inspection found no deterministic investigation candidates to send to the model."],
    });
  }
  const sourceCandidates = sourceCandidatesFromTasks(tasks, input.repoRoot, "single-agent");
  const modelSelection = await resolveRoleModel(input, "single-agent-inspector");
  const response = await completeWithTimeout(
    modelSelection.provider,
    singleAgentRequest(runtime, tasks),
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
    sourceCandidates,
  });
  emitRevalidationProgress(
    runState,
    "single-agent",
    "completed",
    `Revalidated ${candidates.length} single-agent finding${candidates.length === 1 ? "" : "s"}.`,
    candidates.length,
    Math.max(0, responseFindingCount(response.content) - candidates.length),
  );
  const findings = dedupeCandidateFindings(candidates.map((candidate) => candidate.finding)).slice(0, productFindingLimit());
  await saveProductAgentCheckpoint(runState, {
    phase: "revalidation",
    candidates: checkpointCandidatesFromCandidateFindings(candidates, "accepted"),
    finalFindingIds: findings.map((finding) => finding.id),
    metadata: {
      acceptedFindingCount: findings.length,
      rejectedByRevalidationCount: Math.max(0, responseFindingCount(response.content) - candidates.length),
    },
  });
  return productModeSuccess({
    mode: "single-agent",
    provider: response.provider,
    model: response.model,
    findings,
    agentMode: buildSingleAgentModeMetadata(response.provider, response.model, findings, Date.now() - started, {
      candidateCount: discovered.length,
      focusedTaskCount: tasks.length,
      rejectedByRevalidationCount: Math.max(0, responseFindingCount(response.content) - candidates.length),
    }),
    runState,
    started,
    limitations: [
      `Single-agent code inspection investigated ${tasks.length} focused candidate task${tasks.length === 1 ? "" : "s"}.`,
      findings.length === 0 ? "The model response contained no validated product-mode findings." : "",
    ].filter(Boolean),
  });
}

async function runMoaAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
  runState: ProductAgentRunState,
): Promise<ProductAgentScanResult> {
  const allCandidates: CandidateFinding[] = [];
  const specialistRoles = selectedProductAgentSpecialists();
  emitCandidateProgress(runState, "moa-assisted", "running", "Collecting deterministic MoA investigation candidates.");
  const discovered = await discoverInvestigationCandidates(runtime, {
    roleIds: specialistRoles.map((role) => role.id),
    maxCandidates: productDiscoveryLimit(),
  });
  emitCandidateProgress(runState, "moa-assisted", "completed", `Collected ${discovered.length} MoA investigation candidate${discovered.length === 1 ? "" : "s"}.`, discovered.length);
  let model: string | undefined;
  const agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator";
    provider: string;
    model?: string;
    runtimeMs?: number;
    status: "completed";
  }> = [];
  let focusedTaskCount = 0;
  let rejectedByRevalidationCount = 0;
  const allTasks: InvestigationTask[] = [];

  for (const role of specialistRoles) {
    const tasks = buildInvestigationTasks(discovered, {
      roleId: role.id,
      maxTasks: roleFocusedTaskLimit(),
    });
    if (tasks.length === 0) {
      emitTaskProgress(runState, "moa-assisted", "skipped", `${role.label} had no focused candidate tasks.`, 0, role.id);
      continue;
    }
    allTasks.push(...tasks);
    focusedTaskCount += tasks.length;
    emitTaskProgress(runState, "moa-assisted", "running", `${role.label} is inspecting ${tasks.length} focused task${tasks.length === 1 ? "" : "s"}.`, tasks.length, role.id);
    const sourceCandidates = sourceCandidatesFromTasks(tasks, input.repoRoot, "moa-specialist", role.id);
    const modelSelection = await resolveRoleModel(input, role.id as ProductAgentRoleId);
    const roleStarted = Date.now();
    const response = await completeWithTimeout(
      modelSelection.provider,
      specialistRequest(role, runtime, tasks, "moa-assisted"),
      modelSelection.providerConfig,
      modelTimeoutMs(modelSelection.providerConfig?.timeoutMs),
    );
    const roleRuntimeMs = Date.now() - roleStarted;
    model = response.model;
    agentRuns.push({
      id: role.id,
      label: role.label,
      role: "specialist",
      provider: response.provider,
      model: response.model,
      runtimeMs: roleRuntimeMs,
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
      sourceCandidates,
    });
    rejectedByRevalidationCount += Math.max(0, responseFindingCount(response.content) - candidates.length);
    emitTaskProgress(runState, "moa-assisted", "completed", `${role.label} returned ${candidates.length} locally revalidated candidate${candidates.length === 1 ? "" : "s"}.`, tasks.length, role.id);
    allCandidates.push(...candidates);
  }
  await saveProductAgentCheckpoint(runState, {
    phase: "task",
    tasks: checkpointTasksFromInvestigationTasks(allTasks, undefined, "completed"),
    candidates: [
      ...checkpointCandidatesFromInvestigationTasks(allTasks, "moa-specialist", "pending"),
      ...checkpointCandidatesFromCandidateFindings(allCandidates, "accepted"),
    ],
    metadata: {
      candidateCount: discovered.length,
      focusedTaskCount,
      specialistCandidateCount: allCandidates.length,
      rejectedByRevalidationCount,
    },
  });

  if (allCandidates.length === 0) {
    return productModeSuccess({
      mode: "moa-assisted",
      provider: input.provider.id,
      ...(model ? { model } : {}),
      findings: [],
      agentMode: buildMoaModeMetadata({
        provider: input.provider.id,
        model,
        agentRuns,
        specialistRoles,
        findings: [],
        candidateCount: discovered.length,
        acceptedCount: 0,
        rejectedCount: 0,
        needsReviewCount: 0,
        runtimeMs: Date.now() - started,
        focusedTaskCount,
        rejectedByRevalidationCount,
      }),
      runState,
      started,
      limitations: [
        discovered.length === 0
          ? "MoA found no deterministic investigation candidates to send to specialist agents."
          : "MoA specialist responses produced no locally revalidated candidate findings.",
      ],
    });
  }

  const judgeSelection = await resolveRoleModel(input, "moa-false-positive-judge");
  const judgeResult = await judgeCandidatesInBatches(
    "false-positive judge",
    judgeSelection,
    allCandidates,
    "moa-assisted",
  );
  model = judgeResult.model;
  agentRuns.push({
    id: "moa-false-positive-judge",
    label: "False-positive Judge",
    role: "judge",
    provider: judgeResult.provider,
    model: judgeResult.model,
    runtimeMs: judgeResult.runtimeMs,
    status: "completed",
  });
  const judgmentCounts = judgeResult.counts;
  const judgedCandidates = judgeResult.judgedCandidates;
  emitRevalidationProgress(
    runState,
    "moa-assisted",
    "completed",
    `False-positive judge accepted ${judgmentCounts.accepted} and rejected ${judgmentCounts.rejected} candidate${judgmentCounts.accepted + judgmentCounts.rejected === 1 ? "" : "s"}.`,
    judgmentCounts.accepted,
    judgmentCounts.rejected,
  );

  const aggregatorSelection = await resolveRoleModel(input, "moa-aggregator");
  const aggregationLimitations: string[] = [];
  let aggregated: CandidateFinding[] = [];
  try {
    const aggregatorStarted = Date.now();
    const aggregatorResponse = await completeWithTimeout(
      aggregatorSelection.provider,
      aggregatorRequest(judgedCandidates, "moa-assisted"),
      aggregatorSelection.providerConfig,
      modelTimeoutMs(aggregatorSelection.providerConfig?.timeoutMs),
    );
    const aggregatorRuntimeMs = Date.now() - aggregatorStarted;
    model = aggregatorResponse.model;
    agentRuns.push({
      id: "moa-aggregator",
      label: "MoA Aggregator",
      role: "aggregator",
      provider: aggregatorResponse.provider,
      model: aggregatorResponse.model,
      runtimeMs: aggregatorRuntimeMs,
      status: "completed",
    });
    aggregated = await parseFindingCandidates({
      raw: aggregatorResponse.content,
      runtime,
      repoRoot: input.repoRoot,
      mode: "moa-assisted",
      source: "moa-aggregator",
      provider: aggregatorResponse.provider,
      model: aggregatorResponse.model,
      sourceCandidates: judgedCandidates,
    });
    rejectedByRevalidationCount += Math.max(0, responseFindingCount(aggregatorResponse.content) - aggregated.length);
  } catch (error) {
    const message = shortError(error instanceof Error ? error.message : String(error));
    aggregationLimitations.push(`MoA aggregator failed safely; judge-accepted locally revalidated findings were retained. ${message}`);
  }
  emitRevalidationProgress(
    runState,
    "moa-assisted",
    "completed",
    `Final aggregation revalidated ${aggregated.length} finding${aggregated.length === 1 ? "" : "s"}.`,
    aggregated.length,
    0,
  );

  const fallbackFindings = judgedCandidates.map((candidate) => candidate.finding);
  const finalFindings = dedupeCandidateFindings((aggregated.length > 0 ? aggregated.map((candidate) => candidate.finding) : fallbackFindings))
    .slice(0, productFindingLimit());
  await saveProductAgentCheckpoint(runState, {
    phase: "revalidation",
    candidates: [
      ...checkpointCandidatesFromCandidateFindings(judgedCandidates, "accepted"),
      ...checkpointCandidatesFromCandidateFindings(aggregated, "accepted"),
    ],
    finalFindingIds: finalFindings.map((finding) => finding.id),
    metadata: {
      candidateCount: allCandidates.length,
      acceptedFindingCount: judgmentCounts.accepted,
      rejectedFindingCount: judgmentCounts.rejected,
      rejectedByRevalidationCount,
      finalFindingCount: finalFindings.length,
    },
  });

  return productModeSuccess({
    mode: "moa-assisted",
    provider: input.provider.id,
    ...(model ? { model } : {}),
    findings: finalFindings,
    agentMode: buildMoaModeMetadata({
      provider: input.provider.id,
      model,
      agentRuns,
      specialistRoles,
      findings: finalFindings,
      candidateCount: allCandidates.length,
      acceptedCount: judgmentCounts.accepted,
      rejectedCount: judgmentCounts.rejected,
      needsReviewCount: judgmentCounts.needsReview,
      runtimeMs: Date.now() - started,
      focusedTaskCount,
      rejectedByRevalidationCount,
    }),
    runState,
    started,
    limitations: [
      `MoA ran ${specialistRoles.length} specialist role(s), a false-positive judge, and an aggregator.`,
      ...aggregationLimitations,
      ...judgeResult.limitations,
      aggregated.length === 0 && fallbackFindings.length > 0 ? "Aggregator output had no validated findings; judge-accepted specialist candidates were retained after local validation." : "",
      finalFindings.length === 0 ? "MoA completed but produced no validated product-mode findings." : "",
    ].filter(Boolean),
  });
}

async function runScannerMoaAgentScan(
  input: ProductAgentScanInput,
  runtime: CodeInspectionRuntime,
  started: number,
  runState: ProductAgentRunState,
): Promise<ProductAgentScanResult> {
  const scannerCandidates = scannerCandidatesFromFindings(input.scannerFindings ?? [], input.repoRoot);
  const allCandidates: CandidateFinding[] = [...scannerCandidates];
  const specialistRoles = selectedProductAgentSpecialists();
  emitCandidateProgress(runState, "scanner-moa-assisted", "running", "Collecting independent Scanner + MoA investigation candidates.");
  const discovered = await discoverInvestigationCandidates(runtime, {
    roleIds: specialistRoles.map((role) => role.id),
    maxCandidates: productDiscoveryLimit(),
  });
  emitCandidateProgress(
    runState,
    "scanner-moa-assisted",
    "completed",
    `Collected ${scannerCandidates.length} scanner candidate${scannerCandidates.length === 1 ? "" : "s"} and ${discovered.length} agent investigation candidate${discovered.length === 1 ? "" : "s"}.`,
    scannerCandidates.length + discovered.length,
  );
  let model: string | undefined;
  const agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator" | "scanner";
    provider: string;
    model?: string;
    runtimeMs?: number;
    status: "completed" | "failed";
  }> = [];
  const limitations: string[] = [];
  let focusedTaskCount = 0;
  let rejectedByRevalidationCount = 0;
  const allTasks: InvestigationTask[] = [];

  if (scannerCandidates.length > 0) {
    agentRuns.push({
      id: "scanner-stack",
      label: "Scanner Stack",
      role: "scanner",
      provider: "hermsec-scanners",
      status: "completed",
    });
  }

  for (const role of specialistRoles) {
    const tasks = buildInvestigationTasks(discovered, {
      roleId: role.id,
      maxTasks: roleFocusedTaskLimit(),
    });
    if (tasks.length === 0) {
      emitTaskProgress(runState, "scanner-moa-assisted", "skipped", `${role.label} had no focused candidate tasks.`, 0, role.id);
      continue;
    }
    allTasks.push(...tasks);
    focusedTaskCount += tasks.length;
    emitTaskProgress(runState, "scanner-moa-assisted", "running", `${role.label} is inspecting ${tasks.length} focused task${tasks.length === 1 ? "" : "s"}.`, tasks.length, role.id);
    const sourceCandidates = sourceCandidatesFromTasks(tasks, input.repoRoot, "moa-specialist", role.id);
    const modelSelection = await resolveRoleModel(input, role.id as ProductAgentRoleId);
    let response: Awaited<ReturnType<ModelProviderAdapter["complete"]>>;
    const roleStarted = Date.now();
    try {
      response = await completeWithTimeout(
        modelSelection.provider,
        specialistRequest(role, runtime, tasks, "scanner-moa-assisted"),
        modelSelection.providerConfig,
        modelTimeoutMs(modelSelection.providerConfig?.timeoutMs),
      );
    } catch (error) {
      const roleRuntimeMs = Date.now() - roleStarted;
      const message = error instanceof Error ? error.message : String(error);
      limitations.push(`${role.label} failed safely: ${message}`);
      agentRuns.push({
        id: role.id,
        label: role.label,
        role: "specialist",
        provider: modelSelection.provider.id,
        ...(modelSelection.providerConfig?.model ? { model: modelSelection.providerConfig.model } : {}),
        runtimeMs: roleRuntimeMs,
        status: "failed",
      });
      continue;
    }
    const roleRuntimeMs = Date.now() - roleStarted;
    model = response.model;
    agentRuns.push({
      id: role.id,
      label: role.label,
      role: "specialist",
      provider: response.provider,
      model: response.model,
      runtimeMs: roleRuntimeMs,
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
      sourceCandidates,
    });
    rejectedByRevalidationCount += Math.max(0, responseFindingCount(response.content) - candidates.length);
    emitTaskProgress(runState, "scanner-moa-assisted", "completed", `${role.label} returned ${candidates.length} locally revalidated candidate${candidates.length === 1 ? "" : "s"}.`, tasks.length, role.id);
    allCandidates.push(...candidates);
  }
  await saveProductAgentCheckpoint(runState, {
    phase: "task",
    tasks: checkpointTasksFromInvestigationTasks(allTasks, undefined, "completed"),
    candidates: [
      ...checkpointCandidatesFromCandidateFindings(scannerCandidates, "pending"),
      ...checkpointCandidatesFromInvestigationTasks(allTasks, "moa-specialist", "pending"),
      ...checkpointCandidatesFromCandidateFindings(allCandidates.filter((candidate) => candidate.finding.agent?.source !== "scanner-backed"), "accepted"),
    ],
    metadata: {
      scannerCandidateCount: scannerCandidates.length,
      agentDiscoveryCandidateCount: discovered.length,
      focusedTaskCount,
      agentCandidateCount: allCandidates.length - scannerCandidates.length,
      rejectedByRevalidationCount,
    },
  });

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
        specialistRoles,
        findings: [],
        scannerCandidateCount: 0,
        agentCandidateCount: 0,
        acceptedCount: 0,
        rejectedCount: 0,
        needsReviewCount: 0,
        runtimeMs: Date.now() - started,
        focusedTaskCount,
        rejectedByRevalidationCount,
      }),
      runState,
      started,
      limitations: ["Scanner + MoA completed but produced no candidate findings to judge."],
    });
  }

  const judgeSelection = await resolveRoleModel(input, "moa-false-positive-judge");
  const judgeResult = await judgeCandidatesInBatches(
    "false-positive judge",
    judgeSelection,
    allCandidates,
    "scanner-moa-assisted",
  );
  model = judgeResult.model;
  agentRuns.push({
    id: "moa-false-positive-judge",
    label: "False-positive Judge",
    role: "judge",
    provider: judgeResult.provider,
    model: judgeResult.model,
    runtimeMs: judgeResult.runtimeMs,
    status: "completed",
  });
  const judgmentCounts = judgeResult.counts;
  const judgedCandidates = judgeResult.judgedCandidates;
  emitRevalidationProgress(
    runState,
    "scanner-moa-assisted",
    "completed",
    `False-positive judge accepted ${judgmentCounts.accepted} and rejected ${judgmentCounts.rejected} combined candidate${judgmentCounts.accepted + judgmentCounts.rejected === 1 ? "" : "s"}.`,
    judgmentCounts.accepted,
    judgmentCounts.rejected,
  );

  const aggregatorSelection = await resolveRoleModel(input, "moa-aggregator");
  let aggregated: CandidateFinding[] = [];
  try {
    const aggregatorStarted = Date.now();
    const aggregatorResponse = await completeRoleWithTimeout(
      "final aggregator",
      aggregatorSelection.provider,
      aggregatorRequest(judgedCandidates, "scanner-moa-assisted"),
      aggregatorSelection.providerConfig,
    );
    const aggregatorRuntimeMs = Date.now() - aggregatorStarted;
    model = aggregatorResponse.model;
    agentRuns.push({
      id: "moa-aggregator",
      label: "Scanner + MoA Aggregator",
      role: "aggregator",
      provider: aggregatorResponse.provider,
      model: aggregatorResponse.model,
      runtimeMs: aggregatorRuntimeMs,
      status: "completed",
    });
    aggregated = await parseFindingCandidates({
      raw: aggregatorResponse.content,
      runtime,
      repoRoot: input.repoRoot,
      mode: "scanner-moa-assisted",
      source: "moa-aggregator",
      provider: aggregatorResponse.provider,
      model: aggregatorResponse.model,
      sourceCandidates: judgedCandidates,
    });
    rejectedByRevalidationCount += Math.max(0, responseFindingCount(aggregatorResponse.content) - aggregated.length);
  } catch (error) {
    const message = shortError(error instanceof Error ? error.message : String(error));
    limitations.push(`Scanner + MoA aggregator failed safely; judge-accepted locally revalidated findings were retained. ${message}`);
  }
  emitRevalidationProgress(
    runState,
    "scanner-moa-assisted",
    "completed",
    `Final Scanner + MoA aggregation revalidated ${aggregated.length} finding${aggregated.length === 1 ? "" : "s"}.`,
    aggregated.length,
    0,
  );

  const finalFindings = finalizeScannerMoaFindings(aggregated, judgedCandidates)
    .slice(0, productFindingLimit());
  await saveProductAgentCheckpoint(runState, {
    phase: "revalidation",
    candidates: [
      ...checkpointCandidatesFromCandidateFindings(judgedCandidates, "accepted"),
      ...checkpointCandidatesFromCandidateFindings(aggregated, "accepted"),
    ],
    finalFindingIds: finalFindings.map((finding) => finding.id),
    metadata: {
      scannerCandidateCount: scannerCandidates.length,
      agentCandidateCount: allCandidates.length - scannerCandidates.length,
      acceptedFindingCount: judgmentCounts.accepted,
      rejectedFindingCount: judgmentCounts.rejected,
      rejectedByRevalidationCount,
      finalFindingCount: finalFindings.length,
    },
  });

  return productModeSuccess({
    mode: "scanner-moa-assisted",
    provider: input.provider.id,
    ...(model ? { model } : {}),
    findings: finalFindings,
    agentMode: buildScannerMoaModeMetadata({
      provider: input.provider.id,
      model,
      agentRuns,
      specialistRoles,
      findings: finalFindings,
      scannerCandidateCount: scannerCandidates.length,
      agentCandidateCount: allCandidates.length - scannerCandidates.length,
      acceptedCount: judgmentCounts.accepted,
      rejectedCount: judgmentCounts.rejected,
      needsReviewCount: judgmentCounts.needsReview,
      runtimeMs: Date.now() - started,
      focusedTaskCount,
      rejectedByRevalidationCount,
    }),
    runState,
    started,
    limitations: [
      ...limitations,
      `Scanner + MoA judged ${allCandidates.length} combined scanner and agent candidate finding${allCandidates.length === 1 ? "" : "s"}.`,
      ...judgeResult.limitations,
      aggregated.length === 0 && judgedCandidates.length > 0 ? "Aggregator output had no validated findings; judge-accepted candidates were retained after local validation." : "",
      finalFindings.length === 0 ? "The false-positive judge and aggregator rejected all candidate findings." : "",
    ].filter(Boolean),
  });
}

function selectedProductAgentSpecialists(): readonly SpecialistRole[] {
  const requested = productSpecialistCount();
  return PRODUCT_AGENT_SPECIALISTS.slice(0, requested);
}

function productSpecialistCount(): number {
  const explicit = boundedEnvInt("HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT", 0, 1, PRODUCT_AGENT_SPECIALISTS.length);
  if (explicit > 0) {
    return explicit;
  }
  const profile = process.env.HERMSEC_PRODUCT_AGENT_PANEL?.trim().toLowerCase()
    || process.env.HERMSEC_PRODUCT_AGENT_PROFILE?.trim().toLowerCase()
    || process.env.HERMSEC_MOA_PANEL_PROFILE?.trim().toLowerCase();
  if (profile === "high" || profile === "deep" || profile === "large" || profile === "7") {
    return Math.min(5, PRODUCT_AGENT_SPECIALISTS.length);
  }
  if (profile === "low" || profile === "fast" || profile === "small" || profile === "5") {
    return Math.min(3, PRODUCT_AGENT_SPECIALISTS.length);
  }
  return Math.min(3, PRODUCT_AGENT_SPECIALISTS.length);
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

function sourceCandidatesFromTasks(
  tasks: readonly InvestigationTask[],
  repoRoot: string,
  source: Extract<AgentFindingMetadata["source"], "single-agent" | "moa-specialist">,
  role?: string,
): EvidenceSourceCandidate[] {
  const generatedAt = new Date().toISOString();
  return tasks.map((task) => ({
    candidateId: task.candidateId,
    finding: normalizeFinding({
      id: task.candidateId,
      title: task.instruction,
      category: categoryFromInvestigationTask(task),
      severity: "medium",
      confidence: "medium",
      description: task.instruction,
      evidence: task.snippet.text,
      remediation: "Review the candidate evidence and apply the smallest defensive fix if the finding is confirmed.",
      tool: "hermsec-candidate-discovery",
      ruleId: `hermsec.discovery.${task.category}`,
      ...(task.suggestedCwe ? { cwe: [task.suggestedCwe] } : {}),
      location: { file: task.file, startLine: task.line, endLine: task.line },
      agent: {
        mode: source === "single-agent" ? "single-agent" : "moa-assisted",
        source,
        provider: "hermsec-local",
        ...(role ? { role } : {}),
        generatedAt,
        candidateIds: [task.candidateId],
      },
      fingerprint: stableId(`${task.candidateId}:${task.file}:${task.line}`, "fp"),
    }, repoRoot),
  }));
}

function categoryFromInvestigationTask(task: InvestigationTask): FindingCategory {
  if (task.category === "secret") return "secret";
  if (task.category === "dependency") return "dependency";
  if (task.category === "config-iac") return "config";
  return "code";
}

function checkpointTasksFromInvestigationTasks(
  tasks: readonly InvestigationTask[],
  fallbackRoleId: string | undefined,
  status: "waiting" | "running" | "completed" | "skipped" | "failed",
): ProductAgentScanCheckpoint["tasks"] {
  const now = new Date().toISOString();
  return tasks.map((task) => ({
    id: task.taskId,
    label: task.instruction,
    phase: "task",
    status,
    updatedAt: now,
    roleId: fallbackRoleId ?? task.roleId,
    candidateIds: [task.candidateId],
    message: `${task.category} candidate at ${task.file}:${task.line}`,
  }));
}

function checkpointCandidatesFromInvestigationTasks(
  tasks: readonly InvestigationTask[],
  source: "single-agent" | "moa-specialist",
  status: "pending" | "accepted" | "rejected",
): ProductAgentScanCheckpoint["candidates"] {
  const now = new Date().toISOString();
  return tasks.map((task) => ({
    id: task.candidateId,
    source,
    status,
    updatedAt: now,
    title: task.instruction,
    roleId: task.roleId,
    message: `${task.file}:${task.line}`,
  }));
}

function checkpointCandidatesFromCandidateFindings(
  candidates: readonly CandidateFinding[],
  status: "pending" | "accepted" | "rejected",
): ProductAgentScanCheckpoint["candidates"] {
  const now = new Date().toISOString();
  return candidates.map((candidate) => {
    const message = candidate.finding.location?.file
      ? `${candidate.finding.location.file}${candidate.finding.location.startLine ? `:${candidate.finding.location.startLine}` : ""}`
      : undefined;
    return {
      id: candidate.candidateId,
      source: candidate.finding.agent?.source ?? "moa-specialist",
      status,
      updatedAt: now,
      title: candidate.finding.title,
      ...(candidate.finding.agent?.role ? { roleId: candidate.finding.agent.role } : {}),
      findingId: candidate.finding.id,
      fingerprint: candidate.finding.fingerprint,
      ...(message ? { message } : {}),
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

function singleAgentRequest(runtime: CodeInspectionRuntime, tasks: readonly InvestigationTask[]): ModelRequest {
  return jsonRequest([
    "You are Hermsec single-agent product security inspection.",
    "You receive bounded output from list_files, search_code, and read_file_snippet helpers. You cannot request shell commands, package execution, installs, or network access.",
    "This is an agent-only candidate-first scan. Use only the supplied candidate tasks and repository evidence.",
    "Return ONLY one JSON object with a findings array.",
    findingSchemaInstruction(),
    "Only report concrete defensive findings supported by the supplied candidate file paths and snippets. Preserve the supplied candidateId for each finding. Use the candidate location file and line exactly. Prefer no finding over speculation.",
    "Context:",
    JSON.stringify(redactForModel({
      files: runtime.listFiles({ limit: 160 }),
      candidateTasks: candidatePromptContext(tasks),
    }).value),
  ].join("\n"));
}

function specialistRequest(role: SpecialistRole, runtime: CodeInspectionRuntime, tasks: readonly InvestigationTask[], mode: ProductAgentScanMode): ModelRequest {
  return jsonRequest([
    `You are the Hermsec MoA specialist: ${role.label}.`,
    role.focus,
    "You receive bounded output from list_files, search_code, and read_file_snippet helpers. You cannot request shell commands, package execution, installs, or network access.",
    mode === "scanner-moa-assisted"
      ? "This is a scanner + MoA hybrid candidate-first scan. Inspect the supplied candidate tasks independently; scanner findings will be judged together with your candidates later."
      : "This is an agent-only candidate-first scan. Use only the supplied candidate tasks and repository evidence.",
    "Return ONLY one JSON object with a findings array.",
    findingSchemaInstruction(),
    "Report only findings supported by supplied candidate snippets and file paths. Preserve the supplied candidateId for each finding. Use the candidate location file and line exactly. If unsure, return an empty findings array.",
    "Context:",
    JSON.stringify(redactForModel({
      files: runtime.listFiles({ limit: 160 }),
      candidateTasks: candidatePromptContext(tasks),
    }).value),
  ].join("\n"));
}

function judgeRequest(candidates: readonly CandidateFinding[], mode: ProductAgentScanMode): ModelRequest {
  return jsonRequest([
    "You are the Hermsec MoA false-positive judge.",
    mode === "scanner-moa-assisted"
      ? "Review scanner-backed and MoA specialist candidates together. Accept candidates with concrete evidence and reject weak scanner noise, uncertain items, or unsupported model claims."
      : "Review candidate findings for support in their own evidence only. Reject speculation, unsupported files, impossible line references, or vague best-practice advice.",
    "Return ONLY JSON: {\"judgments\":[{\"candidateId\":\"...\",\"verdict\":\"accepted|rejected\",\"confidence\":\"low|medium|high\",\"reason\":\"short reason\"}]}",
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
    "Deduplicate accepted candidates into the smallest useful set of final defensive findings.",
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
    "{\"findings\":[{\"candidateId\":\"required supplied candidate id for non-aggregator findings\",\"title\":\"short title\",\"category\":\"code|dependency|secret|supply-chain|config\",\"severity\":\"critical|high|medium|low|info\",\"confidence\":\"low|medium|high\",\"description\":\"defensive description\",\"evidence\":\"quote or paraphrase from supplied snippet\",\"remediation\":\"safe defensive fix\",\"ruleId\":\"stable rule id\",\"cwe\":[\"CWE-...\"],\"location\":{\"file\":\"repo-relative path\",\"startLine\":1,\"endLine\":1},\"sourceFindingIds\":[\"required accepted candidate ids for aggregator findings\"]}]}",
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
  sourceCandidates?: readonly EvidenceSourceCandidate[];
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
    sourceCandidates?: readonly EvidenceSourceCandidate[];
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
  const rawCandidateId = stringValue(raw.candidateId, 120);
  const candidateId = rawCandidateId
    ?? (context.source === "moa-aggregator"
      ? stableId(JSON.stringify({ title, location, evidence, role: context.role }), "candidate")
      : undefined);
  if (!candidateId) {
    return undefined;
  }
  const sourceFindingMetadata = sourceFindingIds.length > 0
    ? sourceFindingIds
    : context.source !== "moa-aggregator"
      ? [candidateId]
    : context.source === "moa-aggregator" && context.sourceCandidates && context.sourceCandidates.length === 1
      ? [context.sourceCandidates[0]!.candidateId]
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

  const revalidation = await revalidateProductFindingEvidence({
    finding,
    runtime: context.runtime,
    ...(context.sourceCandidates ? { sourceCandidates: context.sourceCandidates } : {}),
    requireKnownSourceIds: context.source === "moa-aggregator",
  });
  if (!revalidation.ok) {
    return undefined;
  }

  return { candidateId, finding: revalidation.finding };
}

async function judgeCandidatesInBatches(
  roleLabel: string,
  selection: ProductAgentModelSelection,
  candidates: readonly CandidateFinding[],
  mode: ProductAgentScanMode,
): Promise<{
  judgments: JudgeResult[];
  counts: ReturnType<typeof countJudgments>;
  judgedCandidates: CandidateFinding[];
  provider: string;
  model: string;
  runtimeMs: number;
  limitations: string[];
}> {
  const started = Date.now();
  const batchSize = judgeBatchSize();
  const chunks = chunkArray(candidates, batchSize);
  const judgments: JudgeResult[] = [];
  const limitations: string[] = [];
  let provider: string = selection.provider.id;
  let model = selection.providerConfig?.model ?? selection.provider.id;
  let splitCount = 0;
  let fallbackCount = 0;

  for (let index = 0; index < chunks.length; index += 1) {
    const result = await judgeCandidateBatch({
      roleLabel,
      selection,
      candidates: chunks[index]!,
      mode,
      batchLabel: `${index + 1}/${chunks.length}`,
    });
    judgments.push(...result.judgments);
    provider = result.provider;
    model = result.model;
    splitCount += result.splitCount;
    fallbackCount += result.fallbackCount;
    limitations.push(...result.limitations);
  }

  if (chunks.length > 1 || splitCount > 0) {
    limitations.unshift(
      `False-positive judge reviewed ${candidates.length} candidates in ${chunks.length + splitCount} bounded batch${chunks.length + splitCount === 1 ? "" : "es"}.`,
    );
  }
  if (fallbackCount > 0) {
    limitations.push(
      `${fallbackCount} judge candidate${fallbackCount === 1 ? "" : "s"} rejected after provider errors.`,
    );
  }

  const counts = countJudgments(candidates, judgments);
  return {
    judgments,
    counts,
    judgedCandidates: applyJudgments(candidates, judgments, model),
    provider,
    model,
    runtimeMs: Date.now() - started,
    limitations: [...new Set(limitations)],
  };
}

async function judgeCandidateBatch(input: {
  roleLabel: string;
  selection: ProductAgentModelSelection;
  candidates: readonly CandidateFinding[];
  mode: ProductAgentScanMode;
  batchLabel: string;
}): Promise<{
  judgments: JudgeResult[];
  provider: string;
  model: string;
  splitCount: number;
  fallbackCount: number;
  limitations: string[];
}> {
  try {
    const response = await completeRoleWithTimeout(
      `${input.roleLabel} batch ${input.batchLabel}`,
      input.selection.provider,
      judgeRequest(input.candidates, input.mode),
      input.selection.providerConfig,
    );
    return {
      judgments: parseJudgeResults(response.content),
      provider: response.provider,
      model: response.model,
      splitCount: 0,
      fallbackCount: 0,
      limitations: [],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (input.candidates.length > 1) {
      const midpoint = Math.ceil(input.candidates.length / 2);
      const left = await judgeCandidateBatch({
        ...input,
        candidates: input.candidates.slice(0, midpoint),
        batchLabel: `${input.batchLabel}a`,
      });
      const right = await judgeCandidateBatch({
        ...input,
        candidates: input.candidates.slice(midpoint),
        batchLabel: `${input.batchLabel}b`,
      });
      return {
        judgments: [...left.judgments, ...right.judgments],
        provider: right.provider,
        model: right.model,
        splitCount: left.splitCount + right.splitCount + 1,
        fallbackCount: left.fallbackCount + right.fallbackCount,
        limitations: [
          `False-positive judge split batch ${input.batchLabel} after provider error: ${shortError(message)}.`,
          ...left.limitations,
          ...right.limitations,
        ],
      };
    }

    const candidate = input.candidates[0];
    return {
      judgments: candidate ? [{
        candidateId: candidate.candidateId,
        verdict: "rejected",
        confidence: "low",
        reason: "Judge provider failed for this bounded batch; rejected by fail-closed policy.",
      }] : [],
      provider: input.selection.provider.id,
      model: input.selection.providerConfig?.model ?? input.selection.provider.id,
      splitCount: 0,
      fallbackCount: candidate ? 1 : 0,
      limitations: [
        `False-positive judge rejected batch ${input.batchLabel} by fail-closed policy: ${shortError(message)}.`,
      ],
    };
  }
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
    const verdict = item.verdict === "accepted" || item.verdict === "rejected"
      ? item.verdict
      : "rejected";
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
      verdict: "rejected" as const,
      confidence: "low" as const,
      reason: "No explicit judge decision was returned; rejected by fail-closed policy.",
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
  runState?: ProductAgentRunState;
  started: number;
  limitations: string[];
}): ProductAgentScanResult {
  const agentMode: ReportAgentModeMetadata = {
    ...input.agentMode,
    ...(input.runState ? { checkpointResumed: input.runState.checkpointResumed } : {}),
    ...(input.runState?.checkpointPath ? { checkpointPath: input.runState.checkpointPath } : {}),
  };
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
    agentMode,
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
  metrics: {
    candidateCount?: number;
    focusedTaskCount?: number;
    rejectedByRevalidationCount?: number;
  } = {},
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
    candidateCount: metrics.candidateCount ?? findings.length,
    candidateFindingCount: metrics.candidateCount ?? findings.length,
    focusedTaskCount: metrics.focusedTaskCount ?? findings.length,
    revalidatedCount: findings.length,
    rejectedByRevalidationCount: metrics.rejectedByRevalidationCount ?? 0,
    acceptedFindingCount: findings.length,
    rejectedFindingCount: metrics.rejectedByRevalidationCount ?? 0,
    needsHumanReviewCount: 0,
    totalAgentRuntimeMs: runtimeMs,
    findings: findingMetadataMap(findings),
  };
}

function buildMoaModeMetadata(input: {
  provider: string;
  model?: string | undefined;
  specialistRoles: readonly SpecialistRole[];
  agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator";
    provider: string;
    model?: string;
    runtimeMs?: number;
    status: "completed";
  }>;
  findings: readonly Finding[];
  candidateCount: number;
  acceptedCount: number;
  rejectedCount: number;
  needsReviewCount: number;
  runtimeMs: number;
  focusedTaskCount?: number;
  rejectedByRevalidationCount?: number;
}): ReportAgentModeMetadata {
  return {
    mode: "moa-assisted",
    scanMode: "moa-assisted",
    modeLabel: productModeLabel("moa-assisted"),
    agentsUsed: [
      ...input.specialistRoles.map((role) => role.id),
      "moa-false-positive-judge",
      "moa-aggregator",
    ],
    agents: [
      ...input.agentRuns,
    ],
    candidateCount: input.candidateCount,
    candidateFindingCount: input.candidateCount,
    focusedTaskCount: input.focusedTaskCount ?? input.candidateCount,
    revalidatedCount: input.findings.length,
    rejectedByRevalidationCount: input.rejectedByRevalidationCount ?? 0,
    acceptedFindingCount: input.acceptedCount,
    rejectedFindingCount: input.rejectedCount + (input.rejectedByRevalidationCount ?? 0),
    needsHumanReviewCount: 0,
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
  specialistRoles: readonly SpecialistRole[];
  agentRuns: Array<{
    id: string;
    label: string;
    role: "specialist" | "judge" | "aggregator" | "scanner";
    provider: string;
    model?: string;
    runtimeMs?: number;
    status: "completed" | "failed";
  }>;
  findings: readonly Finding[];
  scannerCandidateCount: number;
  agentCandidateCount: number;
  acceptedCount: number;
  rejectedCount: number;
  needsReviewCount: number;
  runtimeMs: number;
  focusedTaskCount?: number;
  rejectedByRevalidationCount?: number;
}): ReportAgentModeMetadata {
  return {
    mode: "scanner-moa-assisted",
    scanMode: "scanner-moa-assisted",
    modeLabel: productModeLabel("scanner-moa-assisted"),
    agentsUsed: [
      "scanner-stack",
      ...input.specialistRoles.map((role) => role.id),
      "moa-false-positive-judge",
      "moa-aggregator",
    ],
    agents: [
      ...input.agentRuns,
    ],
    candidateCount: input.scannerCandidateCount + input.agentCandidateCount,
    candidateFindingCount: input.scannerCandidateCount + input.agentCandidateCount,
    focusedTaskCount: input.focusedTaskCount ?? input.agentCandidateCount,
    revalidatedCount: input.findings.length,
    rejectedByRevalidationCount: input.rejectedByRevalidationCount ?? 0,
    acceptedFindingCount: input.acceptedCount,
    rejectedFindingCount: input.rejectedCount + (input.rejectedByRevalidationCount ?? 0),
    needsHumanReviewCount: 0,
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
  for (const candidate of candidates) {
    const verdict = byId.get(candidate.candidateId)?.verdict ?? "rejected";
    if (verdict === "accepted") accepted += 1;
    else rejected += 1;
  }
  return { accepted, rejected, needsReview: 0 };
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
  const providerConfig = config ? { ...config, timeoutMs } : { timeoutMs };
  try {
    return await Promise.race([
      provider.complete(request, providerConfig),
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
  const explicit = boundedEnvInt("HERMSEC_PRODUCT_AGENT_MODEL_TIMEOUT_MS", 0, 30_000, 300_000);
  if (explicit > 0) {
    return explicit;
  }
  return Math.min(240_000, Math.max(configuredTimeoutMs ?? 0, 180_000));
}

function productFindingLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_FINDING_LIMIT", 40, 1, 200);
}

function productDiscoveryLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_DISCOVERY_LIMIT", 48, 1, 200);
}

function productFocusedTaskLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_FOCUSED_TASK_LIMIT", 24, 1, 120);
}

function roleFocusedTaskLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_ROLE_TASK_LIMIT", 8, 1, 60);
}

function productCandidateLimit(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT", 80, 1, 300);
}

function scannerCandidateLimit(): number {
  return boundedEnvInt("HERMSEC_SCANNER_MOA_SCANNER_CANDIDATE_LIMIT", 120, 1, 500);
}

function judgeBatchSize(): number {
  return boundedEnvInt("HERMSEC_PRODUCT_AGENT_JUDGE_BATCH_SIZE", 10, 1, 50);
}

function chunkArray<T>(items: readonly T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks.length > 0 ? chunks : [[]];
}

function shortError(message: string): string {
  return message.replace(/\s+/gu, " ").slice(0, 180);
}

function responseFindingCount(raw: string): number {
  const object = parseJsonObject(raw);
  const findings = Array.isArray(object?.findings) ? object.findings : [];
  return findings.length;
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
