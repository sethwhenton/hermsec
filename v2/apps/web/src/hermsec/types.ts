export type HermsecMainView = "chat" | "search" | "automation" | "projects" | "settings";

export type AutomationStatus = "idle" | "running" | "success" | "failed";

export type HermsecChatChoiceAction = "scan-repo" | "set-automation";

export type HermsecChatChoice = {
  id: string;
  label: string;
  description: string;
  action: HermsecChatChoiceAction;
};

export type HermsecChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  choices?: HermsecChatChoice[];
};

export type HermsecAutomation = {
  id: string;
  name: string;
  schedule: string;
  targetProject: string;
  nextRun: string;
  nextRunAt?: string;
  lastResult: AutomationStatus;
  reportFolder: string;
  enabled: boolean;
};

export type HermsecProject = {
  id: string;
  name: string;
  path: string;
  lastScan: string;
  findingCount: number;
  riskLevel: "low" | "medium" | "high";
};

export type HermsecReportPreview = {
  id: string;
  title: string;
  path: string;
  html: string;
};

export type HermsecSettingsState = {
  provider: string;
  model: string;
  apiKeyEnvVar: string;
  apiKeyValue?: string;
  baseUrl: string;
  defaultReportDirectory: string;
  privacyMode: boolean;
  scanMode: "offline" | "online" | "auto";
  automationDefaultSchedule: string;
};
