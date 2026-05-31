import { HermsecTui } from "./App.js";
import { RichHermsecTui } from "./RichApp.js";
import type { TuiRunOptions, TuiRunSummary } from "./types.js";

export async function runTui(options: TuiRunOptions = {}): Promise<TuiRunSummary> {
  const app = new RichHermsecTui(options);
  return app.run();
}

export async function startChat(options: TuiRunOptions = {}): Promise<TuiRunSummary> {
  return runTui(options);
}

export { HermsecTui } from "./App.js";
export { RichHermsecTui } from "./RichApp.js";
export type {
  ChatMessage,
  ModelMode,
  PrivacyMode,
  ReportLocation,
  ScanPreference,
  TuiDoctorCheck,
  TuiDoctorReport,
  TuiIntelSummary,
  TuiReportSummary,
  TuiRunOptions,
  TuiRunSummary,
  TuiScanRequest,
  TuiScanResult,
  TuiScheduleSummary,
  TuiSessionSnapshot,
  TuiSessionSummary,
  TuiState,
  TuiStatus,
  TuiToolbox,
  TuiWorkspace,
  WorkspaceSourceKind,
} from "./types.js";
