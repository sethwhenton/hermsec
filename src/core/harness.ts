import fs from "node:fs/promises";
import path from "node:path";
import type {
  CanonicalAgentRole,
  CanonicalModelResolver,
} from "../agent/canonicalHarness.js";
import { redactForReport } from "../agent/redaction.js";
import { buildVulnerabilityIntelligence } from "../intel/reportEnrichment.js";
import {
  normalizeCredentialEnvName,
  providerCredentialEnv,
} from "../model/credentials.js";
import type { ModelProviderId, ProviderConfig } from "../model/provider.js";
import { selectModelProvider } from "../model/providerRouter.js";
import { renderReport } from "../reports/reportRenderer.js";
import type {
  ReportAgentModeMetadata,
  ReportFormat,
  ReportIntelligenceItem,
} from "../reports/schema.js";
import type {
  CommandResult,
  Finding,
  OutputFormat,
  ScanAssistModeInput,
  ScanMode,
} from "../shared/types.js";
import { stableId } from "../shared/text.js";
import { loadUserConfig } from "../storage/userConfig.js";
import {
  runCanonicalScanOrchestration,
  type CanonicalScanOrchestrationResult,
} from "./canonicalOrchestrator.js";
import { emitScanProgress, type ScanProgressCallback } from "./progress.js";
import {
  resolveScanAssistMode,
  scanAssistModeLabel,
  scanAssistModeSpec,
} from "./scanAssistModes.js";

export type HarnessScanOptions = {
  cwd: string;
  target: string;
  mode: ScanMode;
  assistMode?: ScanAssistModeInput;
  outputDirectory?: string;
  formats: OutputFormat[];
  useModel: boolean;
  runId?: string;
  signal?: AbortSignal;
  resolveModel?: CanonicalModelResolver;
  onProgress?: ScanProgressCallback;
};

type CanonicalModelContext = {
  available: boolean;
  resolveModel?: CanonicalModelResolver;
  fallbackReason?: string;
};

type HarnessProviderConfig = ProviderConfig & {
  provider: ModelProviderId;
  allowRemoteProviders: boolean;
  timeoutMs: number;
};

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

export async function runScan(
  options: HarnessScanOptions,
): Promise<CommandResult> {
  const assistMode = resolveScanAssistMode(options.assistMode);
  const modeSpec = scanAssistModeSpec(assistMode);

  if (!options.useModel && modeSpec.requiresModel && !modeSpec.runsScanners) {
    return {
      ok: false,
      errorCode: "MODEL_PROVIDER_REQUIRED",
      message: `${scanAssistModeLabel(assistMode)} requires model assistance.`,
      remediation:
        "Enable a configured model provider or choose Scanner only mode.",
    };
  }

  const modelContext = options.resolveModel
    ? {
        available: true,
        resolveModel: options.resolveModel,
      }
    : options.useModel && modeSpec.requiresModel
      ? await createCanonicalModelContext(options)
      : { available: false };

  if (
    modeSpec.requiresModel &&
    !modeSpec.runsScanners &&
    !modelContext.available
  ) {
    return {
      ok: false,
      errorCode: "MODEL_PROVIDER_REQUIRED",
      message: `${scanAssistModeLabel(assistMode)} requires an enabled model provider.${modelContext.fallbackReason ? ` ${modelContext.fallbackReason}` : ""}`,
      remediation:
        "Configure a local or approved remote provider, or choose Scanner only mode.",
    };
  }

  const orchestration = await runCanonicalScanOrchestration({
    target: options.target,
    assistMode,
    scanMode: options.mode,
    ...(options.runId ? { runId: options.runId } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    ...(modelContext.resolveModel
      ? { resolveModel: modelContext.resolveModel }
      : {}),
    ...(options.onProgress ? { onProgress: options.onProgress } : {}),
  });

  if (orchestration.terminalStatus === "canceled") {
    return {
      ok: false,
      errorCode: "SCAN_CANCELED",
      message: "The Hermsec scan was canceled.",
      remediation: "Start a new scan when you are ready.",
    };
  }
  if (
    orchestration.terminalStatus === "failed" &&
    orchestration.findings.length === 0
  ) {
    if (agentProviderWasUnavailable(orchestration)) {
      return {
        ok: false,
        errorCode: "MODEL_PROVIDER_REQUIRED",
        message: `${scanAssistModeLabel(assistMode)} requires an enabled model provider.`,
        remediation:
          "Configure a local or approved remote provider, or choose Scanner only mode.",
      };
    }
    return {
      ok: false,
      errorCode: "SCAN_FAILED",
      message: `${scanAssistModeLabel(assistMode)} failed before producing evidence.`,
      remediation:
        orchestration.degradationReasons.join(" ") ||
        "Review scanner and provider readiness, then retry.",
    };
  }

  let intelligence: {
    status: "completed" | "skipped" | "failed";
    message: string;
    items: ReportIntelligenceItem[];
    limitations: string[];
  };
  try {
    intelligence = modeSpec.runsScanners
      ? await runVulnerabilityIntelligence({
          target: orchestration.scan.target,
          findings: orchestration.scan.findings,
          mode: options.mode,
          assistMode,
          runId: orchestration.runId,
          ...(options.signal ? { signal: options.signal } : {}),
          ...(options.onProgress ? { onProgress: options.onProgress } : {}),
        })
      : {
          status: "skipped",
          message:
            "Agent-only mode does not run scanner-backed vulnerability intelligence.",
          items: [],
          limitations: [
            "Agent-only mode does not run scanner-backed vulnerability intelligence.",
          ],
        };
  } catch (error) {
    if (options.signal?.aborted) {
      return canceledScanResult();
    }
    throw error;
  }

  if (options.signal?.aborted) {
    return canceledScanResult();
  }

  const reportStarted = Date.now();
  emitScanProgress(options.onProgress, {
    id: "report-ready",
    runId: orchestration.runId,
    stage: "report",
    label: "Report generation",
    status: "running",
    message: "Writing report artifacts from immutable detector evidence.",
    assistMode,
  });
  if (options.signal?.aborted) {
    return canceledScanResult();
  }
  const workspaceName =
    path.basename(orchestration.scan.target) || "workspace";
  const agentMode = reportMetadataForOrchestration(orchestration);
  let report: Awaited<ReturnType<typeof renderReport>>;
  try {
    report = await renderReport({
      scanRun: orchestration.scan,
      workspaceId: stableId(orchestration.scan.target, "ws"),
      workspaceName,
      ...(options.outputDirectory
        ? { configuredReportDir: options.outputDirectory }
        : {}),
      formats: mapFormats(options.formats),
      target: {
        kind: "local-path",
        value: orchestration.scan.target,
        displayName: workspaceName,
      },
      explanations: {},
      agentSummary: summaryForOrchestration(orchestration, agentMode),
      agentMode,
      intelligence: intelligence.items,
      limitations: [
        ...intelligence.limitations,
        ...orchestration.degradationReasons,
        ...(orchestration.agentResult?.limitations ?? []),
        "Raw scanner and agent detector findings are retained and cannot be erased by model review.",
      ],
      ...(options.signal ? { signal: options.signal } : {}),
    });
    await writeRawDetectorEvidence(
      report.paths.reportDir,
      orchestration,
      options.signal,
    );
    await writeBenchmarkExportIfRequested(
      report.paths.reportDir,
      orchestration,
      options.signal,
    );
  } catch (error) {
    if (options.signal?.aborted) {
      return canceledScanResult();
    }
    throw error;
  }
  if (options.signal?.aborted) {
    return canceledScanResult();
  }
  emitScanProgress(options.onProgress, {
    id: "report-ready",
    runId: orchestration.runId,
    stage: "report",
    label: "Report generation",
    status: "completed",
    message: "Hermsec report artifacts were written.",
    durationMs: Date.now() - reportStarted,
    assistMode,
  });

  const qualifier =
    orchestration.terminalStatus === "success"
      ? ""
      : ` (${orchestration.terminalStatus})`;
  return {
    ok: true,
    message:
      `${scanAssistModeLabel(assistMode)} completed${qualifier}: ` +
      `${orchestration.scan.summary.total} finding(s). Report: ${report.paths.reportDir}`,
    data: {
      scan: orchestration.scan,
      report: report.artifacts,
      orchestration: {
        runId: orchestration.runId,
        mode: orchestration.mode,
        terminalStatus: orchestration.terminalStatus,
        degradationReasons: orchestration.degradationReasons,
        scannerFindings: orchestration.scannerFindings,
        agentFindings: orchestration.agentFindings,
      },
    },
  };
}

async function createCanonicalModelContext(
  options: HarnessScanOptions,
): Promise<CanonicalModelContext> {
  const userConfig = await loadUserConfig();
  const providerId =
    providerIdFromEnv(process.env.HERMSEC_MODEL_PROVIDER) ??
    userConfig.preferredModelProvider ??
    "none";
  const apiKeyEnv =
    normalizeCredentialEnvName(process.env.HERMSEC_MODEL_API_KEY_ENV) ??
    (userConfig.providerCredentialRef?.kind === "env"
      ? userConfig.providerCredentialRef.name
      : providerCredentialEnv[providerId]);
  const baseUrl = process.env.HERMSEC_MODEL_BASE_URL?.trim();
  const model = process.env.HERMSEC_MODEL?.trim();
  const fallbackConfig: HarnessProviderConfig = {
    provider: providerId,
    ...(baseUrl ? { baseUrl } : {}),
    ...(apiKeyEnv ? { apiKeyEnv } : {}),
    ...(model ? { model } : {}),
    allowRemoteProviders:
      process.env.HERMSEC_ALLOW_REMOTE_PROVIDERS === "true" ||
      userConfig.privacyMode !== "local-only",
    timeoutMs: 120_000,
    ...(providerId === "openrouter"
      ? {
          openRouter: {
            allowFallbacks: false,
            dataCollection: "deny",
            captureRouteMetadata: true,
          },
        }
      : {}),
  };
  const fallback = await selectModelProvider(
    fallbackConfig,
    userConfig.privacyMode,
  );
  if (fallback.provider.id === "none") {
    return {
      available: false,
      ...(fallback.fallbackReason
        ? { fallbackReason: fallback.fallbackReason }
        : {}),
    };
  }
  if (options.mode === "offline" && !fallback.health.local) {
    return {
      available: false,
      fallbackReason:
        "Offline scan mode blocks the configured remote model provider.",
    };
  }

  const routes = parseAgentModelRoutes(
    process.env.HERMSEC_AGENT_MODEL_CONFIG,
  );
  const selections = new Map<
    string,
    Awaited<ReturnType<typeof selectModelProvider>>
  >();
  const resolveModel: CanonicalModelResolver = async ({ role }) => {
    const route = canonicalRouteForRole(routes, role);
    if (!route) {
      return {
        provider: fallback.provider,
        providerConfig: fallbackConfig,
      };
    }
    const providerConfig: HarnessProviderConfig = {
      ...fallbackConfig,
      ...route,
      allowRemoteProviders:
        route.allowRemoteProviders ?? fallbackConfig.allowRemoteProviders,
    };
    const key = JSON.stringify(providerConfig);
    const selected =
      selections.get(key) ??
      (await selectModelProvider(providerConfig, userConfig.privacyMode));
    selections.set(key, selected);
    if (
      selected.provider.id === "none" ||
      (options.mode === "offline" && !selected.health.local)
    ) {
      return undefined;
    }
    return {
      provider: selected.provider,
      providerConfig,
    };
  };
  return {
    available: true,
    resolveModel,
  };
}

function canonicalRouteForRole(
  routes: AgentModelRoutes,
  role: CanonicalAgentRole,
): AgentModelRoute | undefined {
  if (role === "single-agent-inspector") {
    return routes.singleAgent;
  }
  return routes.moa?.[role];
}

function reportMetadataForOrchestration(
  orchestration: Readonly<CanonicalScanOrchestrationResult>,
): ReportAgentModeMetadata {
  const agent = orchestration.agentResult;
  const roles = agent?.roles ?? [];
  const judgments = agent?.judgments ?? [];
  const findingMetadata = Object.fromEntries(
    orchestration.findings.map((finding) => [
      finding.id,
      {
        ...(finding.agent?.source
          ? { sourceLabel: finding.agent.source }
          : {}),
        ...(finding.agent?.judge?.verdict
          ? { judgeStatus: finding.agent.judge.verdict }
          : {}),
        ...(finding.agent?.judge?.reason
          ? { judgeReason: finding.agent.judge.reason }
          : {}),
        ...(finding.agent?.role
          ? { agentIds: [finding.agent.role] }
          : {}),
      },
    ]),
  );
  return {
    mode: orchestration.mode,
    scanMode: orchestration.scan.mode,
    modeLabel: scanAssistModeLabel(orchestration.mode),
    terminalStatus: orchestration.terminalStatus,
    ...(orchestration.degradationReasons.length > 0
      ? { degradationReasons: [...orchestration.degradationReasons] }
      : {}),
    rawScannerFindingCount: orchestration.scannerFindings.length,
    rawAgentFindingCount: orchestration.agentFindings.length,
    candidateCount: agent?.candidates.length ?? 0,
    candidateFindingCount: agent?.rawFindings.length ?? 0,
    focusedTaskCount: roles.length,
    acceptedFindingCount: judgments.filter(
      (item) => item.verdict === "accepted",
    ).length,
    rejectedFindingCount: judgments.filter(
      (item) => item.verdict === "rejected",
    ).length,
    needsHumanReviewCount: judgments.filter(
      (item) => item.verdict === "needs-review",
    ).length,
    agents: roles.map((role) => ({
      id: role.role,
      label: role.label,
      role: role.role,
      status: role.status,
    })),
    agentsUsed: roles.map((role) => role.role),
    ...(Object.keys(findingMetadata).length > 0
      ? { findings: findingMetadata }
      : {}),
  };
}

function summaryForOrchestration(
  orchestration: Readonly<CanonicalScanOrchestrationResult>,
  agentMode: ReportAgentModeMetadata,
): {
  provider: string;
  model?: string;
  fallbackReason?: string;
  agentMode: ReportAgentModeMetadata;
  executiveSummary: string;
  priorityActions: string[];
} {
  const usages = orchestration.agentResult?.usages ?? [];
  const firstUsage = usages[0];
  const priorityActions = [
    ...new Set(
      orchestration.findings
        .filter(
          (finding) =>
            finding.severity === "critical" ||
            finding.severity === "high",
        )
        .map((finding) => `${finding.title}: ${finding.remediation}`),
    ),
  ].slice(0, 5);
  const requiresModel = scanAssistModeSpec(orchestration.mode).requiresModel;
  return {
    provider: firstUsage?.provider ?? "none",
    ...(firstUsage?.model ? { model: firstUsage.model } : {}),
    ...(requiresModel && usages.length === 0
      ? {
          fallbackReason:
            "No model request completed; available detector evidence was preserved.",
        }
      : {}),
    agentMode,
    executiveSummary:
      `${scanAssistModeLabel(orchestration.mode)} completed with ` +
      `${orchestration.scan.summary.total} evidence-backed finding(s) and ` +
      `terminal status ${orchestration.terminalStatus}.`,
    priorityActions,
  };
}

async function runVulnerabilityIntelligence(input: {
  target: string;
  findings: readonly Finding[];
  mode: ScanMode;
  assistMode: ReturnType<typeof resolveScanAssistMode>;
  runId: string;
  signal?: AbortSignal;
  onProgress?: ScanProgressCallback;
}): Promise<{
  status: "completed" | "skipped" | "failed";
  message: string;
  items: ReportIntelligenceItem[];
  limitations: string[];
}> {
  const started = Date.now();
  emitScanProgress(input.onProgress, {
    id: "vulnerability-intelligence",
    runId: input.runId,
    stage: "scanner",
    scannerId: "vulnerability-intelligence",
    label: "Vulnerability intelligence",
    status: "running",
    message:
      "Cross-checking dependency inventory and scanner identifiers against advisory feeds.",
    findingCount: input.findings.length,
    assistMode: input.assistMode,
  });
  const intelligence = await resolveVulnerabilityIntelligence({
    target: input.target,
    workspaceId: stableId(input.target, "ws"),
    findings: input.findings,
    mode: intelligenceModeForScan(input.mode),
    ...(input.signal ? { signal: input.signal } : {}),
  });
  emitScanProgress(input.onProgress, {
    id: "vulnerability-intelligence",
    runId: input.runId,
    stage: "scanner",
    scannerId: "vulnerability-intelligence",
    label: "Vulnerability intelligence",
    status: intelligence.status,
    message: intelligence.message,
    findingCount: intelligence.items.length,
    durationMs: Date.now() - started,
    assistMode: input.assistMode,
  });
  return intelligence;
}

async function resolveVulnerabilityIntelligence(input: {
  target: string;
  workspaceId: string;
  findings: readonly Finding[];
  mode: "auto" | "online" | "offline";
  signal?: AbortSignal;
}): Promise<{
  status: "completed" | "skipped" | "failed";
  message: string;
  items: ReportIntelligenceItem[];
  limitations: string[];
}> {
  try {
    const result = await buildVulnerabilityIntelligence({
      ...input,
      findings: [...input.findings],
    });
    const failedSources = result.results
      .filter((source) => source.status === "failed")
      .map((source) => source.source);
    return {
      status: result.status,
      message: result.message,
      items: result.items,
      limitations:
        failedSources.length > 0
          ? [
              `Vulnerability intelligence source failures: ${failedSources.join(", ")}.`,
            ]
          : [],
    };
  } catch (error) {
    if (input.signal?.aborted) {
      throw input.signal.reason instanceof Error
        ? input.signal.reason
        : new DOMException("Operation was aborted.", "AbortError");
    }
    const unsafeMessage =
      error instanceof Error ? error.message : String(error);
    const redacted = redactForReport({ message: unsafeMessage }).value as {
      message?: string;
    };
    const message = redacted.message ?? "Unknown intelligence error.";
    return {
      status: "failed",
      message: `Vulnerability intelligence failed safely: ${message}`,
      items: [],
      limitations: [
        `Vulnerability intelligence failed safely: ${message}`,
      ],
    };
  }
}

function agentProviderWasUnavailable(
  orchestration: Readonly<CanonicalScanOrchestrationResult>,
): boolean {
  const agent = orchestration.agentResult;
  return Boolean(
    agent &&
      agent.usages.length === 0 &&
      agent.roles.length > 0 &&
      agent.roles.every((role) =>
        role.limitations.includes("model-selection-unavailable"),
      ),
  );
}

function canceledScanResult(): CommandResult {
  return {
    ok: false,
    errorCode: "SCAN_CANCELED",
    message: "The Hermsec scan was canceled.",
    remediation: "Start a new scan when you are ready.",
  };
}

function intelligenceModeForScan(
  mode: ScanMode,
): "auto" | "online" | "offline" {
  if (
    mode === "offline" ||
    process.env.HERMSEC_SCANNER_ONLINE_UPDATES === "false"
  ) {
    return "offline";
  }
  return mode === "online" ? "online" : "auto";
}

async function writeRawDetectorEvidence(
  reportDirectory: string,
  orchestration: Readonly<CanonicalScanOrchestrationResult>,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  const payload = {
    schemaVersion: "1.0",
    runId: orchestration.runId,
    mode: orchestration.mode,
    terminalStatus: orchestration.terminalStatus,
    degradationReasons: orchestration.degradationReasons,
    scannerFindings: orchestration.scannerFindings,
    agentFindings: orchestration.agentFindings,
    finalFindings: orchestration.findings,
  };
  const redacted = redactForReport(payload).value;
  await fs.writeFile(
    path.join(reportDirectory, "detector-evidence.json"),
    `${JSON.stringify(redacted, null, 2)}\n`,
    "utf8",
  );
}

async function writeBenchmarkExportIfRequested(
  reportDir: string,
  orchestration: Readonly<CanonicalScanOrchestrationResult>,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  if (process.env.HERMSEC_BENCHMARK_EXPORT_RAW !== "1") {
    return;
  }
  const payload = redactForReport({
    schemaVersion: "1.0",
    scanId: orchestration.scan.id,
    target: orchestration.scan.target,
    generatedAt: orchestration.scan.finishedAt,
    assistMode: orchestration.mode,
    terminalStatus: orchestration.terminalStatus,
    findings: orchestration.scan.findings,
  }).value;
  await fs.writeFile(
    path.join(reportDir, "benchmark-findings.raw.json"),
    `${JSON.stringify(payload, null, 2)}\n`,
    "utf8",
  );
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DOMException("Operation was aborted.", "AbortError");
  }
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
    if (isRecord(parsed.moa)) {
      const moa: Record<string, AgentModelRoute> = {};
      for (const [role, value] of Object.entries(parsed.moa)) {
        const route = routeFromUnknown(value);
        if (route) {
          moa[role] = route;
        }
      }
      if (Object.keys(moa).length > 0) {
        routes.moa = moa;
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
  const apiKeyEnv = normalizeCredentialEnvName(
    stringFromUnknown(value.apiKeyEnv),
  );
  const allowRemoteProviders =
    typeof value.allowRemoteProviders === "boolean"
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
    ...(allowRemoteProviders !== undefined
      ? { allowRemoteProviders }
      : {}),
  };
}

function providerIdFromEnv(
  value: string | undefined,
): ModelProviderId | undefined {
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

function mapFormats(formats: OutputFormat[]): ReportFormat[] {
  const mapped = formats.map((format) =>
    format === "md" ? "markdown" : format,
  ) as ReportFormat[];
  return mapped.length > 0 ? mapped : ["html", "markdown", "json"];
}

function stringFromUnknown(value: unknown): string | undefined {
  return typeof value === "string" && value.trim()
    ? value.trim()
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
