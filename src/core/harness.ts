import path from "node:path";
import fs from "node:fs/promises";
import { runAgentTurn } from "../agent/runtime.js";
import {
  runProductAgentScan,
  type ProductAgentModelSelection,
  type ProductAgentRoleId,
  type ProductAgentScanMode,
} from "../agent/productScan.js";
import type { ModelExplanation } from "../agent/structuredOutput.js";
import { normalizeCredentialEnvName, providerCredentialEnv } from "../model/credentials.js";
import type { ModelProviderId, ProviderConfig } from "../model/provider.js";
import { selectModelProvider } from "../model/providerRouter.js";
import { assistModeFrom, emitScanProgress, type ScanProgressCallback } from "./progress.js";
import { runScan as runLocalScan, summarize } from "./scan.js";
import { buildVulnerabilityIntelligence } from "../intel/reportEnrichment.js";
import { renderReport } from "../reports/reportRenderer.js";
import { stableId } from "../shared/text.js";
import type { CommandResult, Finding, OutputFormat, ScanAssistModeInput, ScanMode, ScannerStatus } from "../shared/types.js";
import type { ReportAgentModeMetadata, ReportIntelligenceItem } from "../reports/schema.js";
import type { ReportFormat } from "../reports/schema.js";
import { loadUserConfig } from "../storage/userConfig.js";

export type HarnessScanOptions = {
  cwd: string;
  target: string;
  mode: ScanMode;
  assistMode?: ScanAssistModeInput;
  outputDirectory?: string;
  formats: OutputFormat[];
  useModel: boolean;
  onProgress?: ScanProgressCallback;
};

export async function runScan(options: HarnessScanOptions): Promise<CommandResult> {
  const assistMode = assistModeFrom(options.assistMode);
  const productAgentMode = isProductAgentMode(assistMode);
  const agentOnlyMode = isAgentOnlyMode(assistMode);
  const scanRun = await runLocalScan({
    target: options.target,
    mode: options.mode,
    assistMode,
    scannerMode: agentOnlyMode ? "none" : "full",
    ...(options.onProgress ? { onProgress: options.onProgress } : {}),
  });
  const workspaceName = path.basename(scanRun.target) || "workspace";
  const modelStarted = Date.now();
  if (options.useModel) {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: modelPhaseLabel(assistMode),
      status: "running",
      message: modelPhaseRunningMessage(assistMode),
      findingCount: scanRun.findings.length,
      assistMode,
    });
  } else {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: modelPhaseLabel(assistMode),
      status: "skipped",
      message: "Model phase skipped because model assistance is disabled.",
      findingCount: scanRun.findings.length,
      assistMode,
    });
  }
  const agent = await explainScanRun(scanRun.findings, { ...options, assistMode, target: scanRun.target });
  if (!agent.ok) {
    if (agent.status) {
      scanRun.scannerStatuses.push(agent.status);
    }
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: modelPhaseLabel(assistMode),
      status: "failed",
      message: agent.message,
      findingCount: scanRun.findings.length,
      durationMs: Date.now() - modelStarted,
      assistMode,
    });
    return {
      ok: false,
      errorCode: agent.errorCode,
      message: agent.message,
      remediation: agent.remediation,
    };
  }
  if (agent.status) {
    scanRun.scannerStatuses.push(agent.status);
  }
  if (agent.findings.length > 0) {
    scanRun.findings = productAgentMode ? agent.findings : mergeFindings(scanRun.findings, agent.findings);
    scanRun.summary = summarize(scanRun.findings);
  } else if (productAgentMode) {
    scanRun.findings = [];
    scanRun.summary = summarize(scanRun.findings);
  }
  if (options.useModel) {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: modelPhaseLabel(assistMode),
      status: agent.summary.provider === "none" && agent.summary.fallbackReason ? "skipped" : "completed",
      message: agent.summary.fallbackReason
        ? `Model phase used fallback summary: ${agent.summary.fallbackReason}`
        : productAgentMode
          ? "Agent-only inspection completed using bounded repository evidence."
          : "Model phase completed using scanner-backed evidence.",
      findingCount: scanRun.findings.length,
      durationMs: Date.now() - modelStarted,
      assistMode,
    });
  }
  const intelligence = agentOnlyMode
    ? {
        status: "skipped" as const,
        message: `${modelPhaseLabel(assistMode)} is agent-only; scanner/advisory enrichment did not run.`,
        items: [],
        limitations: [`${modelPhaseLabel(assistMode)} is agent-only; scanner and advisory enrichment were not run.`],
      }
    : await runVulnerabilityIntelligence(scanRun.target, scanRun.findings, options.mode, assistMode, options.onProgress);
  const reportStarted = Date.now();
  emitScanProgress(options.onProgress, {
    id: "report-ready",
    stage: "report",
    label: "Report ready",
    status: "running",
    message: "Writing HermSec report artifacts.",
    assistMode,
  });
  const report = await renderReport({
    scanRun,
    workspaceId: stableId(scanRun.target, "ws"),
    workspaceName,
    ...(options.outputDirectory ? { configuredReportDir: options.outputDirectory } : {}),
    formats: mapFormats(options.formats),
    target: {
      kind: "local-path",
      value: scanRun.target,
      displayName: workspaceName,
    },
    explanations: agent.explanations,
    agentSummary: agent.summary,
    ...(agent.agentMode ? { agentMode: agent.agentMode } : {}),
    intelligence: intelligence.items,
    limitations: [...intelligence.limitations, ...agent.limitations],
  });
  await writeBenchmarkExportIfRequested(report.paths.reportDir, scanRun);
  emitScanProgress(options.onProgress, {
    id: "report-ready",
    stage: "report",
    label: "Report ready",
    status: "completed",
    message: "HermSec report artifacts were written.",
    durationMs: Date.now() - reportStarted,
    assistMode,
  });

  return {
    ok: true,
    message: `Scan completed: ${scanRun.summary.total} finding(s). Report: ${report.paths.reportDir}`,
    data: {
      scan: scanRun,
      report: report.artifacts,
    },
  };
}

async function runVulnerabilityIntelligence(
  target: string,
  findings: Awaited<ReturnType<typeof runLocalScan>>["findings"],
  mode: ScanMode,
  assistMode: ReturnType<typeof assistModeFrom>,
  onProgress?: ScanProgressCallback,
): Promise<{
  status: "completed" | "skipped" | "failed";
  message: string;
  items: ReportIntelligenceItem[];
  limitations: string[];
}> {
  const intelligenceStarted = Date.now();
  emitScanProgress(onProgress, {
    id: "vulnerability-intelligence",
    stage: "scanner",
    scannerId: "vulnerability-intelligence",
    label: "Vulnerability intelligence",
    status: "running",
    message: "Cross-checking dependency inventory and scanner identifiers against KEV/CVE advisory feeds.",
    findingCount: findings.length,
    assistMode,
  });
  const intelligence = await resolveVulnerabilityIntelligence({
    target,
    workspaceId: stableId(target, "ws"),
    findings,
    mode: intelligenceModeForScan(mode),
  });
  emitScanProgress(onProgress, {
    id: "vulnerability-intelligence",
    stage: "scanner",
    scannerId: "vulnerability-intelligence",
    label: "Vulnerability intelligence",
    status: intelligence.status,
    message: intelligence.message,
    findingCount: intelligence.items.length,
    durationMs: Date.now() - intelligenceStarted,
    assistMode,
  });
  return intelligence;
}

async function resolveVulnerabilityIntelligence(input: {
  target: string;
  workspaceId: string;
  findings: Awaited<ReturnType<typeof runLocalScan>>["findings"];
  mode: "auto" | "online" | "offline";
}): Promise<{
  status: "completed" | "skipped" | "failed";
  message: string;
  items: ReportIntelligenceItem[];
  limitations: string[];
}> {
  try {
    const result = await buildVulnerabilityIntelligence(input);
    const failedSources = result.results
      .filter((source) => source.status === "failed")
      .map((source) => source.source);
    const limitations = failedSources.length > 0
      ? [`Vulnerability intelligence source failures: ${failedSources.join(", ")}.`]
      : [];
    return {
      status: result.status,
      message: result.message,
      items: result.items,
      limitations,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: "failed",
      message: `Vulnerability intelligence failed safely: ${message}`,
      items: [],
      limitations: [`Vulnerability intelligence failed safely: ${message}`],
    };
  }
}

function intelligenceModeForScan(mode: ScanMode): "auto" | "online" | "offline" {
  if (mode === "offline" || process.env.HERMSEC_SCANNER_ONLINE_UPDATES === "false") {
    return "offline";
  }
  return mode === "online" ? "online" : "auto";
}

async function writeBenchmarkExportIfRequested(reportDir: string, scanRun: Awaited<ReturnType<typeof runLocalScan>>): Promise<void> {
  if (process.env.HERMSEC_BENCHMARK_EXPORT_RAW !== "1") {
    return;
  }
  const exportPath = path.join(reportDir, "benchmark-findings.raw.json");
  await fs.writeFile(exportPath, `${JSON.stringify({
    schemaVersion: "1.0",
    scanId: scanRun.id,
    target: scanRun.target,
    generatedAt: scanRun.finishedAt,
    findings: scanRun.findings,
  }, null, 2)}\n`, "utf8");
}

async function explainScanRun(
  findings: Awaited<ReturnType<typeof runLocalScan>>["findings"],
  options: HarnessScanOptions & { assistMode: ReturnType<typeof assistModeFrom>; target: string },
): Promise<AssistPhaseResult> {
  if (!options.useModel) {
    if (isProductAgentMode(options.assistMode)) {
      return {
        ok: false,
        findings: [],
        explanations: {},
        summary: {
          provider: "none",
          fallbackReason: "Model disabled with --no-model.",
        },
        errorCode: "MODEL_PROVIDER_REQUIRED",
        message: `${modelPhaseLabel(options.assistMode)} requires model assistance; --no-model cannot run this mode.`,
        remediation: "Enable model assistance or choose deep-assisted mode.",
        limitations: ["Product agent mode was not run because model assistance was disabled."],
      };
    }
    return {
      ok: true,
      findings: [],
      explanations: {},
      summary: {
        provider: "none",
        fallbackReason: "Model disabled with --no-model.",
      },
      limitations: [],
    };
  }

  const userConfig = await loadUserConfig();
  const providerId = providerIdFromEnv(process.env.HERMSEC_MODEL_PROVIDER) ?? userConfig.preferredModelProvider ?? "none";
  const apiKeyEnv = normalizeCredentialEnvName(process.env.HERMSEC_MODEL_API_KEY_ENV) ?? (userConfig.providerCredentialRef?.kind === "env"
    ? userConfig.providerCredentialRef.name
    : providerCredentialEnv[providerId]);
  const baseUrl = process.env.HERMSEC_MODEL_BASE_URL?.trim();
  const model = process.env.HERMSEC_MODEL?.trim();
  const providerConfig: HarnessProviderConfig = {
    provider: providerId,
    ...(baseUrl ? { baseUrl } : {}),
    ...(apiKeyEnv ? { apiKeyEnv } : {}),
    ...(model ? { model } : {}),
    allowRemoteProviders: process.env.HERMSEC_ALLOW_REMOTE_PROVIDERS === "true" || userConfig.privacyMode !== "local-only",
    timeoutMs: modelTimeoutMs(findings.length),
  };
  const agentModelRoutes = parseAgentModelRoutes(process.env.HERMSEC_AGENT_MODEL_CONFIG);
  const selection = await selectModelProvider(
    providerConfig,
    userConfig.privacyMode,
  );

  if (isProductAgentMode(options.assistMode)) {
    if (selection.provider.id === "none") {
      const reason = selection.fallbackReason ? ` ${selection.fallbackReason}` : "";
      return {
        ok: false,
        findings: [],
        explanations: {},
        summary: {
          provider: "none",
          ...(selection.fallbackReason ? { fallbackReason: selection.fallbackReason } : {}),
        },
        errorCode: "MODEL_PROVIDER_REQUIRED",
        message: `${modelPhaseLabel(options.assistMode)} requires an enabled model provider.${reason}`,
        remediation: "Enable a local or approved remote model provider, or choose deep-assisted mode for scanner-backed reporting.",
        limitations: [`${modelPhaseLabel(options.assistMode)} did not run because no model provider was available.`],
      };
    }
    if (options.mode === "offline" && !selection.health.local) {
      return {
        ok: false,
        findings: [],
        explanations: {},
        summary: {
          provider: selection.provider.id,
          fallbackReason: "Offline scan mode does not allow remote model providers for product agent modes.",
        },
        errorCode: "MODEL_PROVIDER_REQUIRED",
        message: `${modelPhaseLabel(options.assistMode)} requires a local model provider when scan mode is offline.`,
        remediation: "Use a local provider such as Ollama, switch scan mode to auto/online, or choose deep-assisted mode.",
        limitations: ["Remote model provider was blocked by offline scan mode."],
      };
    }
    const productResult = await runProductAgentScan({
      repoRoot: options.target,
      mode: options.assistMode,
      provider: selection.provider,
      ...(providerConfig ? { providerConfig } : {}),
      ...(options.assistMode === "scanner-moa-assisted" ? { scannerFindings: findings } : {}),
      modelResolver: createProductModelResolver({
        routes: agentModelRoutes,
        mode: options.assistMode,
        fallbackProviderConfig: providerConfig,
        privacyMode: userConfig.privacyMode,
      }),
    });
    if (!productResult.ok) {
      return {
        ok: false,
        findings: [],
        explanations: {},
        summary: {
          provider: productResult.provider,
          fallbackReason: productResult.message,
        },
        status: productResult.status,
        errorCode: productResult.errorCode,
        message: productResult.message,
        remediation: productResult.remediation,
        limitations: productResult.limitations,
      };
    }
    return {
      ok: true,
      findings: productResult.findings,
      explanations: {},
      summary: {
        provider: productResult.provider,
        ...(productResult.model ? { model: productResult.model } : {}),
        executiveSummary: productResult.executiveSummary,
        priorityActions: productResult.priorityActions,
      },
      status: productResult.status,
      limitations: productResult.limitations,
      agentMode: productResult.agentMode,
    };
  }

  const agentTurn = await runAgentTurn({
    message: agentPromptForAssistMode(options.assistMode),
    findings,
    provider: selection.provider,
    providerConfig,
    privacyMode: userConfig.privacyMode,
    offlineMode: options.mode === "offline" && !selection.health.local,
    forceIntent: "explain_findings",
  });

  const fallbackReason = [selection.fallbackReason, agentTurn.modelSkippedReason].filter(Boolean).join("; ");
  return {
    ok: true,
    findings: [],
    explanations: agentTurn.explanations ?? {},
    summary: {
      provider: agentTurn.providerUsed,
      ...(fallbackReason ? { fallbackReason } : {}),
      executiveSummary: agentTurn.message,
      priorityActions: agentTurn.priorityActions ?? [],
    },
    limitations: [],
  };
}

type AgentModelRoute = {
  provider?: ModelProviderId;
  baseUrl?: string;
  model?: string;
  apiKeyEnv?: string;
  allowRemoteProviders?: boolean;
};

type AgentModelRoutes = {
  singleAgent?: AgentModelRoute;
  moa?: Record<string, AgentModelRoute>;
};

type HarnessProviderConfig = ProviderConfig & {
  provider: ModelProviderId;
  allowRemoteProviders: boolean;
  timeoutMs: number;
};

function createProductModelResolver(input: {
  routes: AgentModelRoutes;
  mode: ProductAgentScanMode;
  fallbackProviderConfig: HarnessProviderConfig;
  privacyMode: Awaited<ReturnType<typeof loadUserConfig>>["privacyMode"];
}): (roleId: ProductAgentRoleId) => Promise<ProductAgentModelSelection | undefined> {
  return async (roleId) => {
    const route = input.mode === "single-agent"
      ? input.routes.singleAgent
      : input.routes.moa?.[roleId];
    if (!route) {
      return undefined;
    }
    const providerConfig = {
      ...input.fallbackProviderConfig,
      ...route,
      allowRemoteProviders: route.allowRemoteProviders ?? input.fallbackProviderConfig.allowRemoteProviders,
    };
    const selected = await selectModelProvider(providerConfig, input.privacyMode);
    if (selected.provider.id === "none") {
      return undefined;
    }
    return {
      provider: selected.provider,
      providerConfig,
    };
  };
}

function parseAgentModelRoutes(raw: string | undefined): AgentModelRoutes {
  if (!raw?.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return {};
    }
    const routes: AgentModelRoutes = {};
    const singleAgent = routeFromUnknown(parsed.singleAgent);
    if (singleAgent) {
      routes.singleAgent = singleAgent;
    }
    const moa = parsed.moa;
    if (isRecord(moa)) {
      const roleRoutes: Record<string, AgentModelRoute> = {};
      for (const [roleId, value] of Object.entries(moa)) {
        const route = routeFromUnknown(value);
        if (route) {
          roleRoutes[roleId] = route;
        }
      }
      if (Object.keys(roleRoutes).length > 0) {
        routes.moa = roleRoutes;
      }
    }
    return routes;
  } catch {
    return {};
  }
}

function routeFromUnknown(value: unknown): AgentModelRoute | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const provider = providerIdFromEnv(stringFromUnknown(value.provider));
  const baseUrl = stringFromUnknown(value.baseUrl);
  const model = stringFromUnknown(value.model);
  const apiKeyEnv = normalizeCredentialEnvName(stringFromUnknown(value.apiKeyEnv));
  const allowRemoteProviders = typeof value.allowRemoteProviders === "boolean"
    ? value.allowRemoteProviders
    : undefined;
  if (!provider && !baseUrl && !model && !apiKeyEnv) {
    return undefined;
  }
  return {
    ...(provider ? { provider } : {}),
    ...(baseUrl ? { baseUrl } : {}),
    ...(model ? { model } : {}),
    ...(apiKeyEnv ? { apiKeyEnv } : {}),
    ...(allowRemoteProviders !== undefined ? { allowRemoteProviders } : {}),
  };
}

function stringFromUnknown(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function agentPromptForAssistMode(assistMode: HarnessScanOptions["assistMode"]): string {
  return [
    "Deep assisted report: explain, prioritize, and connect these completed scanner findings for the Hermsec report.",
    "Use only supplied scanner evidence.",
    "Do not create findings, identifiers, files, packages, or line numbers that are not present in the scanner data.",
    "When findings appear related, say so only through the supplied evidence in the explanation fields.",
  ].join(" ");
}

function mapFormats(formats: OutputFormat[]): ReportFormat[] {
  const mapped = formats.map((format) => (format === "md" ? "markdown" : format)) as ReportFormat[];
  return mapped.length ? mapped : ["html", "markdown", "json"];
}

function modelTimeoutMs(findingCount: number): number {
  return Math.min(120_000, Math.max(45_000, 30_000 + findingCount * 2_500));
}

type AssistPhaseResult =
  | {
      ok: true;
      findings: Finding[];
      explanations: Record<string, ModelExplanation | undefined>;
      summary: {
        provider: string;
        model?: string;
        fallbackReason?: string;
        executiveSummary?: string;
        priorityActions?: string[];
      };
      status?: ScannerStatus;
      limitations: string[];
      agentMode?: ReportAgentModeMetadata;
    }
  | {
      ok: false;
      findings: [];
      explanations: Record<string, ModelExplanation | undefined>;
      summary: {
        provider: string;
        fallbackReason?: string;
      };
      status?: ScannerStatus;
      errorCode: string;
      message: string;
      remediation: string;
      limitations: string[];
    };

function isProductAgentMode(mode: ReturnType<typeof assistModeFrom>): mode is ProductAgentScanMode {
  return mode === "single-agent" || mode === "moa-assisted" || mode === "scanner-moa-assisted";
}

function isAgentOnlyMode(mode: ReturnType<typeof assistModeFrom>): boolean {
  return mode === "single-agent" || mode === "moa-assisted";
}

function modelPhaseLabel(mode: ReturnType<typeof assistModeFrom>): string {
  if (mode === "single-agent") return "Single-agent inspection";
  if (mode === "moa-assisted") return "MoA-assisted inspection";
  if (mode === "scanner-moa-assisted") return "Scanner + MoA inspection";
  return "Deep model triage";
}

function modelPhaseRunningMessage(mode: ReturnType<typeof assistModeFrom>): string {
  if (mode === "single-agent") {
    return "Model is inspecting bounded repository snippets for additional product findings.";
  }
  if (mode === "moa-assisted") {
    return "Model specialists, false-positive judge, and aggregator are inspecting bounded repository snippets.";
  }
  if (mode === "scanner-moa-assisted") {
    return "Scanners and MoA candidates are being judged and aggregated into a final evidence-bound set.";
  }
  return "Model is supporting triage over scanner-confirmed evidence.";
}

function mergeFindings(scannerFindings: readonly Finding[], agentFindings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const merged: Finding[] = [];
  for (const finding of [...scannerFindings, ...agentFindings]) {
    if (seen.has(finding.fingerprint)) {
      continue;
    }
    seen.add(finding.fingerprint);
    merged.push(finding);
  }
  return merged;
}

function providerIdFromEnv(value: string | undefined): ModelProviderId | undefined {
  switch (value?.trim()) {
    case "none":
    case "ollama":
    case "openrouter":
    case "openai":
    case "claude":
    case "gemini":
    case "opencode-go":
    case "openai-compatible":
      return value.trim() as ModelProviderId;
    case "anthropic":
      return "claude";
    case "google-gemini":
      return "gemini";
    case "ollama-local":
    case "ollama-cloud":
      return "ollama";
    default:
      return undefined;
  }
}
