import path from "node:path";
import { runScan as runLocalScan } from "./scan.js";
import { renderReport } from "../reports/reportRenderer.js";
import { stableId } from "../shared/text.js";
import type { CommandResult, OutputFormat, ScanMode } from "../shared/types.js";
import type { ReportFormat } from "../reports/schema.js";

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
    agentSummary: {
      provider: options.useModel ? "configured-model-or-fallback" : "none",
      fallbackReason: options.useModel ? "Model adapters are optional; scanner evidence was preserved locally." : "Model disabled with --no-model.",
    },
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

function mapFormats(formats: OutputFormat[]): ReportFormat[] {
  const mapped = formats.map((format) => (format === "md" ? "markdown" : format)) as ReportFormat[];
  return mapped.length ? mapped : ["html", "markdown", "json"];
}
