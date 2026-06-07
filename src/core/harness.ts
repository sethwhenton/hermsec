import path from "node:path";
import { runAgentTurn } from "../agent/runtime.js";
import { providerCredentialEnv } from "../model/credentials.js";
import { selectModelProvider } from "../model/providerRouter.js";
import { runScan as runLocalScan } from "./scan.js";
import { renderReport } from "../reports/reportRenderer.js";
import { stableId } from "../shared/text.js";
import type { CommandResult, OutputFormat, ScanMode } from "../shared/types.js";
import type { ReportFormat } from "../reports/schema.js";
import { loadUserConfig } from "../storage/userConfig.js";

export type HarnessScanOptions = {
  cwd: string;
  target: string;
  mode: ScanMode;
  outputDirectory?: string;
  formats: OutputFormat[];
  useModel: boolean;
};

export async function runScan(options: HarnessScanOptions): Promise<CommandResult> {
  const scanRun = await runLocalScan({
    target: options.target,
    mode: options.mode,
  });
  const workspaceName = path.basename(scanRun.target) || "workspace";
  const agent = await explainScanRun(scanRun.findings, options);
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
    message: "Explain these scanner findings for the Hermsec report. Use only supplied scanner evidence.",
    findings,
    provider: selection.provider,
    providerConfig,
    privacyMode: userConfig.privacyMode,
    offlineMode: options.mode === "offline" && !selection.health.local,
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

function mapFormats(formats: OutputFormat[]): ReportFormat[] {
  const mapped = formats.map((format) => (format === "md" ? "markdown" : format)) as ReportFormat[];
  return mapped.length ? mapped : ["html", "markdown", "json"];
}

function modelTimeoutMs(findingCount: number): number {
  return Math.min(120_000, Math.max(45_000, 30_000 + findingCount * 2_500));
}
