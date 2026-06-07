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
  scanMode: string;
}

export type AutomationFrequency = "daily" | "every-3-days" | "weekly";

export interface AutomationSettings {
  enabled: boolean;
  frequency: AutomationFrequency;
  time: string;
  lastRunAt?: string;
  lastCheckedAt?: string;
  lastResult?: string;
  lastReportDir?: string;
  lastProjectStateFingerprint?: string;
}

export interface AppSettings {
  general: GeneralSettings;
  defaultProjectDir: string;
  defaultReportDir: string;
  activeModelId?: string;
  automation: AutomationSettings;
  providers: ProviderConfig[];
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
