import { ensureHermsecAppData } from "../storage/appData.js";
import { getActiveWorkspace, getWorkspace, listWorkspaces, type WorkspaceProfile } from "../storage/workspaceStore.js";
import { loadUserConfig } from "../storage/userConfig.js";
import { runScan as runHarnessScan } from "../core/harness.js";
import { runDoctor as runDoctorChecks } from "../doctor/checks.js";
import { updateIntel as updateIntelCommand } from "../intel/update.js";
import { listReports as listStoredReports } from "../reports/reportStore.js";
import { listSchedules as listStoredSchedules } from "../scheduler/schedules.js";
import { addWorkspace as addWorkspaceProfile, useWorkspace as useWorkspaceProfile } from "../workspace/workspaceManager.js";
import type { ReportIndexEntry, ReportSummary } from "../reports/schema.js";
import type { ScheduleRecord, ScheduleStatus } from "../scheduler/types.js";
import type { CommandResult, ScannerStatus, ScanRun } from "../shared/types.js";
import { runTui } from "./index.js";
import type {
  TuiDoctorReport,
  TuiIntelSummary,
  TuiReportSummary,
  TuiScanRequest,
  TuiScanResult,
  TuiScheduleSummary,
  TuiState,
  TuiStatus,
  TuiToolbox,
  TuiWorkspace,
} from "./types.js";

type HarnessScanPayload = {
  scan?: ScanRun;
  report?: {
    htmlPath?: string;
    markdownPath?: string;
    summaryPath?: string;
    documentPath?: string;
    directory?: string;
  };
};

type IntelPayload = {
  summaryText?: string;
  feed?: Array<{
    id: string;
    title: string;
    source: string;
    whyShown?: string;
  }>;
  summary?: {
    items?: unknown[];
  };
};

export async function launchChat(options: {
  cwd: string;
  args: string[];
  firstRun: boolean;
}): Promise<CommandResult> {
  const summary = await runTui({
    cwd: options.cwd,
    skipOnboarding: !options.firstRun,
    tools: createCliToolbox(options.cwd),
  });
  return {
    ok: true,
    message:
      summary.exitReason === "non-interactive"
        ? "Hermsec chat needs an interactive terminal. Use `hermsec --help` for commands."
        : "Chat session finished.",
    data: summary,
  };
}

export async function runOnboarding(options: { cwd: string; args: string[] }): Promise<CommandResult> {
  const layout = await ensureHermsecAppData();
  const config = await loadUserConfig();
  return {
    ok: true,
    message: `Onboarding ready. Config: ${layout.configFile}. Reports: ${config.customReportDir ?? layout.reportsDir}`,
    data: {
      appDataDir: layout.appDataDir,
      configPath: layout.configFile,
      reportDirectory: config.customReportDir ?? layout.reportsDir,
      privacyMode: config.privacyMode,
    },
  };
}

export function createCliToolbox(cwd: string): TuiToolbox {
  return {
    loadState: () => loadTuiState(),
    doctor: () => runTuiDoctor(cwd),
    scan: (request) => runTuiScan(cwd, request),
    listReports: (workspace) => runTuiReportList(cwd, workspace),
    listSchedules: (workspace) => runTuiScheduleList(workspace),
    updateIntel: (workspace) => runTuiIntelUpdate(cwd, workspace),
    addWorkspace: (workspace) => runTuiWorkspaceAdd(workspace),
    useWorkspace: (workspace) => runTuiWorkspaceUse(workspace),
  };
}

async function loadTuiState(): Promise<Partial<TuiState>> {
  const [workspaces, activeWorkspace] = await Promise.all([
    listWorkspaces(),
    getActiveWorkspace(),
  ]);
  const config = await loadUserConfig();
  const active = activeWorkspace ?? workspaces[0];
  const state: Partial<TuiState> = {
    workspaces: workspaces.map(toTuiWorkspace),
    privacyMode: active?.privacyMode ?? config.privacyMode,
    scanMode: active?.scanMode ?? "auto",
    reportLocation: "custom",
    reportDir: active?.reportDir ?? config.customReportDir,
  };

  if (active?.id) {
    state.activeWorkspaceId = active.id;
  }

  return state;
}

async function runTuiDoctor(cwd: string): Promise<CommandResult<TuiDoctorReport>> {
  const result = await runDoctorChecks({ cwd, json: false });
  if (!result.ok) {
    return {
      ok: false,
      errorCode: result.errorCode,
      message: result.message,
      ...(result.remediation ? { remediation: result.remediation } : {}),
    };
  }
  const doctor = result.data;
  if (!doctor) {
    return {
      ok: false,
      errorCode: "TUI_DOCTOR_PAYLOAD_MISSING",
      message: "The doctor tool completed but did not return readiness data for the TUI.",
    };
  }

  return {
    ok: true,
    message: result.message,
    data: {
      summary: result.message.split(/\r?\n/)[1] ?? result.message,
      checks: doctor.checks.map((check) => ({
        label: check.label,
        status: mapDoctorStatus(check.status),
        message: check.message,
      })),
    },
  };
}

async function runTuiScan(cwd: string, request: TuiScanRequest): Promise<CommandResult<TuiScanResult>> {
  const workspace = request.workspaceId ? await getWorkspace(request.workspaceId) : undefined;
  const result = await runHarnessScan({
    cwd,
    target: request.target,
    mode: request.mode,
    ...(workspace?.reportDir ? { outputDirectory: workspace.reportDir } : {}),
    formats: ["json", "md", "html"],
    useModel: true,
  });

  if (!result.ok) {
    return {
      ok: false,
      errorCode: result.errorCode,
      message: result.message,
      ...(result.remediation ? { remediation: result.remediation } : {}),
    };
  }

  const payload = result.data as HarnessScanPayload | undefined;
  if (!payload?.scan) {
    return {
      ok: false,
      errorCode: "TUI_SCAN_PAYLOAD_MISSING",
      message: "The scanner harness completed but did not return scan data for the TUI.",
      remediation: "Run `hermsec scan <path>` to inspect the scriptable scan output.",
    };
  }

  const reportPath = reportPathFromPayload(payload);
  const scanResult: TuiScanResult = {
    id: payload.scan.id,
    target: payload.scan.target,
    status: "completed",
    mode: payload.scan.mode,
    preference: request.preference,
    startedAt: payload.scan.startedAt,
    finishedAt: payload.scan.finishedAt,
    summary: payload.scan.summary,
    scannerStatuses: payload.scan.scannerStatuses.map(toTuiScannerStatus),
  };
  if (reportPath) {
    scanResult.reportPath = reportPath;
  }

  return {
    ok: true,
    message: result.message,
    data: scanResult,
  };
}

async function runTuiReportList(
  cwd: string,
  workspace: TuiWorkspace | undefined,
): Promise<CommandResult<TuiReportSummary[]>> {
  const result = await listStoredReports({ cwd, ...(workspace?.id ? { workspaceId: workspace.id } : {}) });
  if (!result.ok) {
    return {
      ok: false,
      errorCode: result.errorCode,
      message: result.message,
      ...(result.remediation ? { remediation: result.remediation } : {}),
    };
  }

  const data = result.data as { reports?: ReportIndexEntry[] } | undefined;
  return {
    ok: true,
    message: result.message,
    data: (data?.reports ?? []).map((report) => ({
      title: report.scanId,
      path: report.htmlPath || report.markdownPath || report.reportDir,
      createdAt: report.generatedAt,
      summary: formatReportTotals(report.totals),
    })),
  };
}

async function runTuiScheduleList(
  workspace: TuiWorkspace | undefined,
): Promise<CommandResult<TuiScheduleSummary[]>> {
  const schedules = await listStoredSchedules(workspace?.id);
  return {
    ok: true,
    message: schedules.length ? `${schedules.length} schedule(s) configured.` : "No schedules configured.",
    data: schedules.map(toTuiSchedule),
  };
}

async function runTuiIntelUpdate(
  cwd: string,
  workspace: TuiWorkspace | undefined,
): Promise<CommandResult<TuiIntelSummary>> {
  const result = await updateIntelCommand({
    cwd,
    ...(workspace?.id ? { workspaceId: workspace.id } : {}),
    offline: false,
  });
  if (!result.ok) {
    return {
      ok: false,
      errorCode: result.errorCode,
      message: result.message,
      ...(result.remediation ? { remediation: result.remediation } : {}),
    };
  }

  const payload = result.data as IntelPayload | undefined;
  const summaryItems = payload?.summaryText
    ?.split(/\r?\n/)
    .map((line) => line.replace(/^\d+\.\s*/, "").trim())
    .filter((line) => line.length > 0);
  const feedItems = payload?.feed?.map((item) =>
    `${item.source}: ${item.title}${item.whyShown ? ` (${item.whyShown})` : ""}`,
  );
  return {
    ok: true,
    message: result.message,
    data: {
      status: "complete",
      message: result.message,
      items: summaryItems && summaryItems.length > 0
        ? summaryItems
        : feedItems && feedItems.length > 0
        ? feedItems
        : [`Cached ${payload?.summary?.items?.length ?? 0} intelligence item(s).`],
    },
  };
}

async function runTuiWorkspaceAdd(workspace: TuiWorkspace): Promise<CommandResult<TuiWorkspace>> {
  if (workspace.sourceKind === "github-url") {
    return {
      ok: true,
      message: "GitHub URL workspaces are kept in this TUI session until clone/token support is enabled.",
      data: workspace,
    };
  }

  const saved = await addWorkspaceProfile({
    rootPath: workspace.target,
    displayName: workspace.name,
    ...(workspace.reportDir ? { reportDir: workspace.reportDir } : {}),
    privacyMode: workspace.privacyMode,
    scanMode: "auto",
  });
  return {
    ok: true,
    message: `Workspace saved: ${saved.displayName}`,
    data: toTuiWorkspace(saved),
  };
}

async function runTuiWorkspaceUse(workspace: TuiWorkspace): Promise<CommandResult<TuiWorkspace>> {
  if (workspace.sourceKind === "github-url") {
    return {
      ok: true,
      message: "Using GitHub URL workspace for this TUI session.",
      data: workspace,
    };
  }

  const saved = await useWorkspaceProfile(workspace.id);
  return {
    ok: true,
    message: `Using workspace ${saved.displayName}: ${saved.rootPath}`,
    data: toTuiWorkspace(saved),
  };
}

function toTuiWorkspace(workspace: WorkspaceProfile): TuiWorkspace {
  return {
    id: workspace.id,
    name: workspace.displayName,
    target: workspace.rootPath,
    sourceKind: "local",
    reportLocation: "custom",
    privacyMode: workspace.privacyMode,
    modelMode: "none",
    scanPreference: "full",
    createdAt: workspace.createdAt,
    lastUsedAt: workspace.updatedAt,
    reportDir: workspace.reportDir,
    scannerReadiness: "Stored workspace profile.",
  };
}

function mapDoctorStatus(status: "pass" | "warn" | "fail" | "skip"): TuiStatus {
  switch (status) {
    case "pass":
      return "ready";
    case "warn":
      return "missing";
    case "fail":
      return "failed";
    case "skip":
      return "skipped";
  }
}

function toTuiScannerStatus(status: ScannerStatus): { label: string; status: TuiStatus; message: string } {
  return {
    label: status.label,
    status: mapScannerStatus(status.status),
    message: status.message,
  };
}

function mapScannerStatus(status: ScannerStatus["status"]): TuiStatus {
  switch (status) {
    case "ready":
      return "ready";
    case "missing":
      return "missing";
    case "skipped":
      return "skipped";
    case "failed":
      return "failed";
    case "completed":
      return "complete";
  }
}

function reportPathFromPayload(payload: HarnessScanPayload): string | undefined {
  return (
    payload.report?.htmlPath ??
    payload.report?.markdownPath ??
    payload.report?.summaryPath ??
    payload.report?.documentPath ??
    payload.report?.directory
  );
}

function formatReportTotals(totals: ReportSummary): string {
  return `CRITICAL ${totals.critical}, HIGH ${totals.high}, MEDIUM ${totals.medium}, LOW ${totals.low}, INFO ${totals.info}`;
}

function toTuiSchedule(schedule: ScheduleRecord): TuiScheduleSummary {
  const summary: TuiScheduleSummary = {
    id: schedule.id,
    target: schedule.targetPath,
    cadence: schedule.time ?? schedule.cron ?? schedule.trigger,
    mode: schedule.mode,
    status: schedule.enabled ? mapScheduleStatus(schedule.lastStatus) : "skipped",
  };
  if (schedule.nextRunAt) {
    summary.nextRunAt = schedule.nextRunAt;
  }
  if (schedule.lastRunAt) {
    summary.lastRunAt = schedule.lastRunAt;
  }
  return summary;
}

function mapScheduleStatus(status: ScheduleStatus | undefined): TuiStatus {
  switch (status) {
    case "success":
      return "complete";
    case "partial":
      return "ready";
    case "skipped":
      return "skipped";
    case "failed":
    case "blocked":
      return "failed";
    default:
      return "ready";
  }
}
