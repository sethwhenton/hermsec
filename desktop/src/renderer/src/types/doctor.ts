export type DoctorStatus = "pass" | "warn" | "fail" | "skip";
export type DoctorProgressStatus = DoctorStatus | "running";
export type DoctorRequirement = "required" | "recommended" | "optional";

export interface DoctorCheck {
  id: string;
  label: string;
  status: DoctorStatus;
  requirement: DoctorRequirement;
  message: string;
  remediation?: string;
}

export interface DoctorSummary {
  pass: number;
  warn: number;
  fail: number;
  skip: number;
}

export interface DoctorConnectivityCheck {
  id: string;
  label: string;
  url: string;
  status: Exclude<DoctorStatus, "skip">;
  latencyMs?: number;
  statusCode?: number;
  message: string;
}

export interface DoctorGroupSummary {
  id: "required" | "scanners" | "internet" | "providers";
  label: string;
  ready: number;
  total: number;
  status: DoctorStatus;
  message: string;
}

export interface DoctorProgressEvent {
  id: string;
  runId?: string;
  groupId: DoctorGroupSummary["id"];
  label: string;
  status: DoctorProgressStatus;
  message: string;
  requirement?: DoctorRequirement;
  latencyMs?: number;
  statusCode?: number;
  at: number;
}

export interface DoctorRunResult {
  ok: boolean;
  message: string;
  generatedAt: string;
  durationMs: number;
  cwd: string;
  appDataDir: string;
  reportDirectory: string;
  checks: DoctorCheck[];
  summary: DoctorSummary;
  connectivity: DoctorConnectivityCheck[];
  groups: DoctorGroupSummary[];
  healthScore: number;
  status: "ready" | "attention" | "blocked";
}
