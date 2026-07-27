export interface ExplainReportRequest {
  reportPath: string;
  question: string;
  previousPrompt?: string;
}

export interface ExplainReportResult {
  ok: boolean;
  message: string;
  reportPath?: string;
  intent?: string;
  copyLabel?: string;
  copyText?: string;
  promptFilePath?: string;
  error?: string;
}

export interface ReportConversationMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ConverseReportRequest {
  reportPath?: string;
  projectPath?: string;
  question: string;
  history?: ReportConversationMessage[];
}

export interface ConverseReportResult {
  ok: boolean;
  message: string;
  reportPath?: string;
  usedModel?: boolean;
  modelId?: string;
  modelStatus?:
    | "success"
    | "not-configured"
    | "rate-limited"
    | "authentication-failed"
    | "provider-unavailable"
    | "request-failed"
    | "empty-response"
    | "invalid-response"
    | "timeout"
    | "canceled"
    | "transport-error";
  error?: string;
}

export interface ReportControlResult {
  ok: boolean;
  message: string;
}

export interface LatestReportResult {
  ok: boolean;
  message?: string;
  projectPath?: string;
  reportDir?: string;
  htmlPath?: string;
  dashboardHtmlPath?: string;
  onepagerHtmlPath?: string;
  onepagerPdfPath?: string;
  runId?: string;
  assistMode?: import("./scan").HermsecProductScanAssistMode;
  assistModeLabel?: string;
  terminalStatus?: import("./scan").ScanTerminalStatus;
  degradationReasons?: string[];
  generatedAt?: string;
  projectState?: import("./scan").ProjectStateFingerprint;
  error?: string;
}

export interface DashboardBundleRequest {
  reportPathOrDir: string;
}

export interface DashboardBundleResult {
  ok: boolean;
  html?: string;
  reportDir?: string;
  dashboardHtmlPath?: string;
  onepagerHtmlPath?: string;
  onepagerPdfPath?: string;
  message?: string;
  error?: string;
}

export interface OpenArtifactRequest {
  path: string;
}

export interface OpenArtifactResult {
  ok: boolean;
  message: string;
}
