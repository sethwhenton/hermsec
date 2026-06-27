import type { HermsecProductScanAssistMode } from "./scan";
import type { ScannerSettings } from "./scanners";

export type ProviderAuthKind = "api_key" | "custom" | "environment";
export type ProviderApiFormat = "openai-compatible" | "anthropic" | "gemini" | "custom" | "cursor";

export interface ProviderModelDiscovery {
  status: "idle" | "success" | "error";
  message?: string;
  modelCount?: number;
  lastCheckedAt?: string;
}

export interface ModelConfig {
  id: string;
  label: string;
  enabled: boolean;
}

export interface ProviderConfig {
  id: string;
  displayName: string;
  baseUrl: string;
  apiFormat?: ProviderApiFormat;
  presetId?: string;
  description?: string;
  logoUrl?: string;
  websiteUrl?: string;
  supportsModelDiscovery?: boolean;
  authKind: ProviderAuthKind;
  apiKeyEnvVar?: string;
  apiKey?: string;
  enabled: boolean;
  models: ModelConfig[];
  modelDiscovery?: ProviderModelDiscovery;
}

export interface ProviderPreset {
  id: string;
  displayName: string;
  description: string;
  baseUrl: string;
  apiFormat: ProviderApiFormat;
  apiKeyEnvVar?: string;
  logoUrl?: string;
  websiteUrl?: string;
  enabled: boolean;
  supportsModelDiscovery: boolean;
  status: "available" | "coming-soon";
  models: ModelConfig[];
}

export interface GeneralSettings {
  language: string;
  autoAcceptPermissions: boolean;
  terminalShell: string;
  privacyMode: boolean;
  scanMode: HermsecProductScanAssistMode;
  thinkingLevel: "fast" | "balanced" | "deep";
  contextWindow: "compact" | "standard" | "large";
}

export type AgentReasoningDepth = "fast" | "balanced" | "deep";
export type MoAInspectionPresetId = "low-panel" | "high-panel";

export interface AgentModelSelection {
  providerId?: string;
  modelId?: string;
}

export interface SingleAgentScanConfig {
  providerId?: string;
  modelId?: string;
  reasoningDepth: AgentReasoningDepth;
  maxToolRounds: number;
}

export interface MoAInspectionPresetConfig {
  presetId: MoAInspectionPresetId;
  panelSize: 3 | 5 | 7;
  debateRounds: number;
  consensusThreshold: "majority" | "supermajority" | "coordinator";
  roleModels?: Record<string, AgentModelSelection>;
}

export interface AgentScanSettings {
  singleAgent: SingleAgentScanConfig;
  moa: MoAInspectionPresetConfig;
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
  scanMode?: HermsecProductScanAssistMode;
}

export interface AppSettings {
  general: GeneralSettings;
  defaultProjectDir: string;
  defaultReportDir: string;
  activeModelId?: string;
  activeProviderId?: string;
  automation: AutomationSettings;
  providers: ProviderConfig[];
  scanners: ScannerSettings;
  agents?: AgentScanSettings;
}

export interface ProviderTestRequest {
  providerId?: string;
  baseUrl: string;
  apiFormat?: ProviderApiFormat;
  apiKey?: string;
  apiKeyEnvVar?: string;
}

export interface ProviderTestResult {
  ok: boolean;
  status?: number;
  message: string;
  latencyMs: number;
  modelCount?: number;
  models?: ModelConfig[];
}

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};
