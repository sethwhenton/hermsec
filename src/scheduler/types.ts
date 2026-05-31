export const scheduleTriggers = ["daily", "weekdays", "cron"] as const;
export type ScheduleTrigger = (typeof scheduleTriggers)[number];

export const scheduleStatuses = ["success", "partial", "skipped", "failed", "blocked"] as const;
export type ScheduleStatus = (typeof scheduleStatuses)[number];

export const scheduleModes = ["offline", "online", "auto"] as const;
export type ScheduleMode = (typeof scheduleModes)[number];

export const changePolicies = ["scan-if-git-changed", "scan-always"] as const;
export type ChangePolicy = (typeof changePolicies)[number];

export const scanDepths = ["auto", "changed-files", "full"] as const;
export type ScanDepth = (typeof scanDepths)[number];

export const scanScopes = ["none", "changed-files", "dependency", "full"] as const;
export type ScanScope = (typeof scanScopes)[number];

export type ScheduleRecord = {
  schemaVersion: 1;
  id: string;
  workspaceId: string;
  targetPath: string;
  enabled: boolean;
  trigger: ScheduleTrigger;
  time?: string;
  cron?: string;
  timezone: string;
  mode: ScheduleMode;
  changePolicy: ChangePolicy;
  scanDepth: ScanDepth;
  nextRunAt?: string;
  lastRunAt?: string;
  lastStatus?: ScheduleStatus;
  disabledReason?: string;
};

export type SchedulesFile = {
  schemaVersion: 1;
  schedules: ScheduleRecord[];
};

export type BaselineRecord = {
  schemaVersion: 1;
  workspaceId: string;
  repoRoot: string;
  branch?: string;
  headCommit?: string;
  lastSuccessfulScanId?: string;
  workingTreeFingerprint?: string;
  scannedAt: string;
};

export type GitFileChange = {
  path: string;
  status: "added" | "modified" | "deleted" | "renamed" | "copied" | "untracked" | "unknown";
  oldPath?: string;
};

export type GitState = {
  kind: "git";
  repoRoot: string;
  gitDir: string;
  branch?: string;
  headCommit?: string;
  hasCommits: boolean;
  statusEntries: GitFileChange[];
  workingTreeFingerprint: string;
};

export type GitChangeDetection =
  | {
      kind: "changed" | "unchanged" | "initial";
      state: GitState;
      baseline?: BaselineRecord;
      changedFiles: GitFileChange[];
      reason: string;
    }
  | {
      kind: "not-git" | "git-error";
      repoRoot?: string;
      changedFiles: GitFileChange[];
      reason: string;
      error?: string;
    };

export type ChangeBucket =
  | "dependency"
  | "security-sensitive"
  | "source"
  | "docs-only"
  | "generated-vendor"
  | "other";

export type ChangeClassification = {
  changedFiles: string[];
  effectiveFiles: string[];
  ignoredFiles: string[];
  buckets: ChangeBucket[];
  scanScope: ScanScope;
};

export type ScheduleRunDecision = {
  scheduleId: string;
  workspaceId: string;
  shouldRun: boolean;
  status: "due" | "not-due" | "skipped" | "blocked";
  reason: string;
  mode: ScheduleMode;
  scanScope: ScanScope;
  targetPath: string;
  dueAt?: string;
  git?: GitChangeDetection;
  classification?: ChangeClassification;
};
