import path from "node:path";

import { defaultReportDir, toPosixPath } from "../shared/paths.js";
import type {
  ChatMessage,
  ScanPreference,
  TuiDoctorReport,
  TuiReportSummary,
  TuiScheduleSummary,
  TuiSessionSummary,
  TuiState,
  TuiStatus,
  TuiWorkspace,
} from "./types.js";

const STATUS_LABELS: Record<TuiStatus, string> = {
  pending: "PENDING",
  running: "RUNNING",
  ready: "READY",
  missing: "MISSING",
  skipped: "SKIPPED",
  failed: "FAILED",
  complete: "COMPLETE",
};

export function formatStatus(status: TuiStatus): string {
  return STATUS_LABELS[status];
}

export function formatTopBar(state: TuiState): string {
  const workspace = activeWorkspace(state);
  const workspaceLabel = workspace?.name ?? "no workspace";
  const lastScan = workspace?.lastScanAt ?? state.lastScan?.finishedAt ?? "never";
  const reportPath = workspace?.reportDir ?? state.reportDir ?? defaultReportDir();
  return `Hermsec | workspace: ${workspaceLabel} | mode: ${state.privacyMode} | last scan: ${lastScan} | reports: ${reportPath}`;
}

export function formatStatusRail(state: TuiState): string[] {
  const workspace = activeWorkspace(state);
  const latestSummary = state.lastScan?.summary;
  const findings = latestSummary
    ? `CRITICAL ${latestSummary.critical}, HIGH ${latestSummary.high}, MEDIUM ${latestSummary.medium}, LOW ${latestSummary.low}, INFO ${latestSummary.info}`
    : "none yet";
  const latestReport = state.lastScan?.reportPath ?? state.reports[0]?.path ?? workspace?.reportDir ?? state.reportDir ?? defaultReportDir();
  const scanProgress = state.lastScan ? `${state.lastScan.status} (${state.lastScan.preference})` : "idle";

  return [
    `Workspace: ${workspace ? workspace.target : "add one with /workspace add <path>"}`,
    `Mode: privacy ${state.privacyMode}, scan ${state.scanMode}`,
    `Scanner readiness: ${workspace?.scannerReadiness ?? state.lastDoctor?.summary ?? "unknown"}`,
    `Scan progress: ${scanProgress}`,
    `Findings: ${findings}`,
    `Reports: ${latestReport}`,
    `Model: ${modelLabel(state.modelMode)}`,
    `Session: ${state.activeSessionId}`,
  ];
}

export function formatTranscript(messages: ChatMessage[], max = 10): string[] {
  return messages.slice(-max).map((message) => {
    const speaker = message.role === "user" ? "You" : message.role === "system" ? "System" : "Hermsec";
    return `${speaker}: ${message.text}`;
  });
}

export function renderFrame(state: TuiState, width: number): string {
  const divider = "-".repeat(Math.min(Math.max(width, 40), 120));
  const topBar = clampLine(formatTopBar(state), width);
  const transcript = formatTranscript(state.transcript);
  const status = formatStatusRail(state);

  if (width < 92) {
    return [
      divider,
      topBar,
      divider,
      ...transcript,
      "",
      "Status",
      ...status.map((line) => `- ${line}`),
      "",
      "Type /help for commands. Type /exit to leave.",
      divider,
    ].join("\n");
  }

  const rightWidth = 34;
  const leftWidth = Math.max(40, width - rightWidth - 5);
  const rows = Math.max(transcript.length, status.length, 7);
  const body: string[] = [];

  body.push(divider);
  body.push(clampLine(topBar, width));
  body.push(divider);
  body.push(`${padRight("Chat transcript", leftWidth)} | Status rail`);
  body.push(`${"-".repeat(leftWidth)} | ${"-".repeat(rightWidth)}`);

  for (let index = 0; index < rows; index += 1) {
    const left = transcript[index] ?? "";
    const right = status[index] ?? "";
    body.push(`${padRight(clampLine(left, leftWidth), leftWidth)} | ${clampLine(right, rightWidth)}`);
  }

  body.push("");
  body.push("you> type /help for commands, /exit to leave");
  body.push(divider);
  return body.join("\n");
}

export function formatHelp(): string {
  return [
    "Hermsec is restricted to security workflow actions. It cannot edit code, run arbitrary shell commands, install packages, or collect secrets.",
    "",
    "Commands:",
    "- /help                 Show commands and safety boundaries",
    "- /commands             Alias for /help",
    "- /doctor               Check local readiness through the Hermsec doctor tool",
    "- /scan <path>          Scan a local path or GitHub URL through the approved scan harness",
    "- /scan changed         Scan changed files for the active workspace",
    "- /reports              Show local reports Hermsec knows about",
    "- /workspace add <path> Add a workspace for this session",
    "- /workspace list       Show workspaces",
    "- /workspace use <name> Switch active workspace",
    "- /intel                Show or update the curated security feed",
    "- /schedule list        Show configured schedules",
    "- /sessions             List saved chat sessions for the active workspace",
    "- /sessions new         Save the current session and start a fresh one",
    "- /sessions current     Show the current session summary",
    "- /history [count]      Show recent messages from this session",
    "- /exit                 Leave the TUI",
    "",
    "Natural language works for safe intents, for example: scan this folder, show reports, run doctor, update security news.",
  ].join("\n");
}

export function formatHistory(messages: ChatMessage[], limit = 20): string {
  const count = Math.max(1, Math.min(limit, 100));
  const visible = messages.slice(-count);
  if (visible.length === 0) {
    return "No messages in this session yet.";
  }

  return [
    `Recent history (${visible.length}/${messages.length} messages):`,
    ...visible.map((message, index) => {
      const speaker = message.role === "user" ? "You" : message.role === "system" ? "System" : "Hermsec";
      return `${index + 1}. ${speaker} [${message.at}]: ${message.text}`;
    }),
  ].join("\n");
}

export function formatDoctor(report: TuiDoctorReport): string {
  return [
    report.summary,
    ...report.checks.map((check) => `- ${formatStatus(check.status)} ${check.label}: ${check.message}`),
  ].join("\n");
}

export function formatReports(reports: TuiReportSummary[]): string {
  if (reports.length === 0) {
    return "No local reports are known yet. Run /scan <path> after the scan harness is connected, or check your configured report folder.";
  }

  return [
    "Local reports:",
    ...reports.map((report, index) => {
      const created = report.createdAt ? ` (${report.createdAt})` : "";
      const summary = report.summary ? ` - ${report.summary}` : "";
      return `${index + 1}. ${report.title}${created}${summary}\n   ${report.path}`;
    }),
  ].join("\n");
}

export function formatSchedules(schedules: TuiScheduleSummary[]): string {
  if (schedules.length === 0) {
    return "No schedules are configured yet. Hermsec will list git-aware schedules here once the scheduler tool is connected.";
  }

  return [
    "Schedules:",
    ...schedules.map((schedule, index) => {
      const next = schedule.nextRunAt ? `, next ${schedule.nextRunAt}` : "";
      const last = schedule.lastRunAt ? `, last ${schedule.lastRunAt}` : "";
      return `${index + 1}. ${schedule.id}: ${schedule.cadence} for ${schedule.target} (${schedule.mode}, ${formatStatus(schedule.status)}${next}${last})`;
    }),
  ].join("\n");
}

export function formatSessions(
  sessions: TuiSessionSummary[],
  activeSessionId: string | undefined,
  currentMessageCount: number,
): string {
  const lines = [
    `Current session: ${activeSessionId ?? "none"} (${currentMessageCount} message${currentMessageCount === 1 ? "" : "s"})`,
  ];

  if (sessions.length === 0) {
    return [
      ...lines,
      "No saved sessions yet. Use /sessions new or /exit to save the current session.",
    ].join("\n");
  }

  return [
    ...lines,
    "Saved sessions:",
    ...sessions.map((session, index) => {
      const marker = session.id === activeSessionId ? "*" : " ";
      const summary = session.compactSummary ? ` - ${session.compactSummary}` : "";
      return `${marker} ${index + 1}. ${session.title} (${session.messageCount} messages, updated ${session.updatedAt})\n   ${session.id}${summary}`;
    }),
  ].join("\n");
}

export function formatWorkspaces(workspaces: TuiWorkspace[], activeWorkspaceId: string | undefined): string {
  if (workspaces.length === 0) {
    return "No workspaces yet. Add one with /workspace add <path> or run onboarding.";
  }

  return [
    "Workspaces:",
    ...workspaces.map((workspace, index) => {
      const marker = workspace.id === activeWorkspaceId ? "*" : " ";
      const summary = workspace.lastFindingSummary ? `, ${workspace.lastFindingSummary}` : "";
      const reportPath = workspace.reportDir ? `, reports ${workspace.reportDir}` : "";
      return `${marker} ${index + 1}. ${workspace.name} - ${workspace.target}${summary}${reportPath}`;
    }),
  ].join("\n");
}

export function scanPreferenceLabel(preference: ScanPreference): string {
  switch (preference) {
    case "changed":
      return "changed files";
    case "dependency-only":
      return "dependency-only";
    case "secrets-only":
      return "secrets-only";
    case "full":
      return "full scan";
  }
}

export function defaultWorkspaceName(target: string): string {
  if (isLikelyUrl(target)) {
    const cleaned = target.replace(/\.git$/i, "");
    const last = cleaned.split(/[/:]/).filter(Boolean).at(-1);
    return last ?? "github-workspace";
  }

  return path.basename(path.resolve(target)) || "workspace";
}

export function isLikelyUrl(target: string): boolean {
  return /^(https?:\/\/|git@|ssh:\/\/)/i.test(target);
}

export function normalizedDisplayPath(value: string): string {
  return isLikelyUrl(value) ? value : toPosixPath(path.resolve(value));
}

export function activeWorkspace(state: TuiState): TuiWorkspace | undefined {
  return state.workspaces.find((workspace) => workspace.id === state.activeWorkspaceId);
}

function modelLabel(mode: TuiState["modelMode"]): string {
  switch (mode) {
    case "none":
      return "no model";
    case "local-provider":
      return "local provider";
    case "cloud-provider":
      return "cloud provider, explicit consent required";
  }
}

function clampLine(value: string, width: number): string {
  if (width <= 4 || value.length <= width) {
    return value;
  }

  return `${value.slice(0, width - 3)}...`;
}

function padRight(value: string, width: number): string {
  return value.length >= width ? value : `${value}${" ".repeat(width - value.length)}`;
}
