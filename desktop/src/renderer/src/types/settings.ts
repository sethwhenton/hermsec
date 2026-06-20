import type { HermsecScanAssistMode } from "./scan";
import type { ScannerSettings } from "./scanners";

export type ProviderAuthKind = "api_key" | "custom" | "environment";

export interface ModelConfig {
  id: string;
  label: string;
  enabled: boolean;
}

export interface ProviderConfig {
  id: string;
  displayName: string;
  baseUrl: string;
  authKind: ProviderAuthKind;
  apiKeyEnvVar?: string;
  apiKey?: string;
  enabled: boolean;
  models: ModelConfig[];
}

export interface GeneralSettings {
  language: string;
  autoAcceptPermissions: boolean;
  terminalShell: string;
  showReasoning: boolean;
  privacyMode: boolean;
  scanMode: HermsecScanAssistMode;
  thinkingLevel: "fast" | "balanced" | "deep";
  contextWindow: "compact" | "standard" | "large";
}

export type AutomationFrequency = "custom-days" | "weekly" | "monthly" | "daily" | "every-3-days";

export interface AutomationSettings {
  enabled: boolean;
  frequency: AutomationFrequency;
  intervalDays?: number;
  time: string;
  lastRunAt?: string;
  lastCheckedAt?: string;
  lastResult?: string;
  lastReportDir?: string;
  lastProjectStateFingerprint?: string;
  scanMode?: HermsecScanAssistMode;
}

export interface AppSettings {
  general: GeneralSettings;
  defaultProjectDir: string;
  defaultReportDir: string;
  activeModelId?: string;
  automation: AutomationSettings;
  providers: ProviderConfig[];
  scanners: ScannerSettings;
}

export interface ProviderTestRequest {
  baseUrl: string;
  apiKey?: string;
  apiKeyEnvVar?: string;
}

export interface ProviderTestResult {
  ok: boolean;
  status?: number;
  message: string;
  latencyMs: number;
}

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};
