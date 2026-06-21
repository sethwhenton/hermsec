import path from "node:path";
import fs from "node:fs/promises";
import { runAgentTurn } from "../agent/runtime.js";
import { providerCredentialEnv } from "../model/credentials.js";
import { selectModelProvider } from "../model/providerRouter.js";
import { assistModeFrom, emitScanProgress, type ScanProgressCallback } from "./progress.js";
import { runScan as runLocalScan } from "./scan.js";
import { buildVulnerabilityIntelligence } from "../intel/reportEnrichment.js";
import { renderReport } from "../reports/reportRenderer.js";
import { stableId } from "../shared/text.js";
import type { CommandResult, OutputFormat, ScanMode } from "../shared/types.js";
import type { ReportIntelligenceItem } from "../reports/schema.js";
import type { ReportFormat } from "../reports/schema.js";
import { loadUserConfig } from "../storage/userConfig.js";

export type HarnessScanOptions = {
  cwd: string;
  target: string;
  mode: ScanMode;
  assistMode?: "scanner-model-summary" | "deep-assisted";
  outputDirectory?: string;
  formats: OutputFormat[];
  useModel: boolean;
  onProgress?: ScanProgressCallback;
};

export async function runScan(options: HarnessScanOptions): Promise<CommandResult> {
  const assistMode = assistModeFrom(options.assistMode);
  const scanRun = await runLocalScan({
    target: options.target,
    mode: options.mode,
    assistMode,
    ...(options.onProgress ? { onProgress: options.onProgress } : {}),
  });
  const workspaceName = path.basename(scanRun.target) || "workspace";
  const intelligenceStarted = Date.now();
  emitScanProgress(options.onProgress, {
    id: "vulnerability-intelligence",
    stage: "scanner",
    scannerId: "vulnerability-intelligence",
    label: "Vulnerability intelligence",
    status: "running",
    message: "Cross-checking dependency inventory and scanner identifiers against KEV/CVE advisory feeds.",
    findingCount: scanRun.findings.length,
    assistMode,
  });
  const intelligence = await resolveVulnerabilityIntelligence({
    target: scanRun.target,
    workspaceId: stableId(scanRun.target, "ws"),
    findings: scanRun.findings,
    mode: intelligenceModeForScan(options.mode),
  });
  emitScanProgress(options.onProgress, {
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
  const modelStarted = Date.now();
  if (options.useModel) {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: assistMode === "deep-assisted" ? "Deep model triage" : "Model summary",
      status: "running",
      message: assistMode === "deep-assisted"
        ? "Model is supporting triage over scanner-confirmed evidence."
        : "Model is summarizing scanner-backed evidence.",
      findingCount: scanRun.findings.length,
      assistMode,
    });
  } else {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: assistMode === "deep-assisted" ? "Deep model triage" : "Model summary",
      status: "skipped",
      message: "Model phase skipped because model assistance is disabled.",
      findingCount: scanRun.findings.length,
      assistMode,
    });
  }
  const agent = await explainScanRun(scanRun.findings, { ...options, assistMode });
  if (options.useModel) {
    emitScanProgress(options.onProgress, {
      id: "model-summary",
      stage: "model",
      label: assistMode === "deep-assisted" ? "Deep model triage" : "Model summary",
      status: agent.summary.provider === "none" && agent.summary.fallbackReason ? "skipped" : "completed",
      message: agent.summary.fallbackReason
        ? `Model phase used fallback summary: ${agent.summary.fallbackReason}`
        : "Model phase completed using scanner-backed evidence.",
      findingCount: scanRun.findings.length,
      durationMs: Date.now() - modelStarted,
      assistMode,
    });
  }
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
    intelligence: intelligence.items,
    limitations: intelligence.limitations,
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
  options: HarnessScanOptions,
) {
  if (!options.useModel) {
    return {
      explanations: {},
      summary: {
        provider: "none",
        fallbackReason: "Model disabled with --no-model.",
      },
    };
  }

  const userConfig = await loadUserConfig();
  const providerId = userConfig.preferredModelProvider ?? "none";
  const apiKeyEnv = userConfig.providerCredentialRef?.kind === "env"
    ? userConfig.providerCredentialRef.name
    : providerCredentialEnv[providerId];
  const providerConfig = {
    provider: providerId,
    ...(apiKeyEnv ? { apiKeyEnv } : {}),
    ...(process.env.HERMSEC_MODEL?.trim() ? { model: process.env.HERMSEC_MODEL.trim() } : {}),
    allowRemoteProviders: userConfig.privacyMode !== "local-only",
    timeoutMs: modelTimeoutMs(findings.length),
  };
  const selection = await selectModelProvider(
    providerConfig,
    userConfig.privacyMode,
  );

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
    explanations: agentTurn.explanations ?? {},
    summary: {
      provider: agentTurn.providerUsed,
      ...(fallbackReason ? { fallbackReason } : {}),
      executiveSummary: agentTurn.message,
      priorityActions: agentTurn.priorityActions ?? [],
    },
  };
}

function agentPromptForAssistMode(assistMode: HarnessScanOptions["assistMode"]): string {
  if (assistMode === "deep-assisted") {
    return [
      "Deep assisted report: explain, prioritize, and connect these completed scanner findings for the Hermsec report.",
      "Use only supplied scanner evidence.",
      "Do not create findings, identifiers, files, packages, or line numbers that are not present in the scanner data.",
      "When findings appear related, say so only through the supplied evidence in the explanation fields.",
    ].join(" ");
  }

  return "Explain these scanner findings for the Hermsec report. Use only supplied scanner evidence.";
}

function mapFormats(formats: OutputFormat[]): ReportFormat[] {
  const mapped = formats.map((format) => (format === "md" ? "markdown" : format)) as ReportFormat[];
  return mapped.length ? mapped : ["html", "markdown", "json"];
}

function modelTimeoutMs(findingCount: number): number {
  return Math.min(120_000, Math.max(45_000, 30_000 + findingCount * 2_500));
}
