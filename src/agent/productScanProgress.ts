import { emitScanProgress, type ScanProgressCallback, type ScanProgressInput } from "../core/progress.js";
import type { ScanProgressDetail, ScanProgressStatus } from "../shared/types.js";
import type { ProductAgentRoleId, ProductAgentScanMode } from "./productScan.js";
import type {
  ProductAgentCheckpointPhase,
  ProductAgentCheckpointResumeMetadata,
} from "./productScanCheckpoint.js";

export type ProductAgentProgressPhase = ProductAgentCheckpointPhase;

export type ProductAgentProgressInput = {
  phase: ProductAgentProgressPhase;
  assistMode: ProductAgentScanMode;
  status: ScanProgressStatus;
  id?: string;
  label?: string;
  message?: string;
  taskId?: string;
  taskLabel?: string;
  roleId?: ProductAgentRoleId | string;
  candidateId?: string;
  candidateCount?: number;
  totalCandidates?: number;
  completedCount?: number;
  acceptedCount?: number;
  rejectedCount?: number;
  needsReviewCount?: number;
  checkpointPath?: string;
  resume?: ProductAgentCheckpointResumeMetadata;
  durationMs?: number;
};

export function emitProductAgentProgress(
  onProgress: ScanProgressCallback | undefined,
  input: ProductAgentProgressInput,
): void {
  emitScanProgress(onProgress, buildProductAgentProgressEvent(input));
}

export function buildProductAgentProgressEvent(input: ProductAgentProgressInput): ScanProgressInput {
  const details = productAgentProgressDetails(input);
  return {
    id: input.id ?? productAgentProgressId(input),
    stage: input.phase,
    label: input.label ?? productAgentPhaseLabel(input.phase),
    status: input.status,
    message: input.message ?? productAgentPhaseMessage(input.phase, input.status),
    assistMode: input.assistMode,
    ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
    ...(details.length > 0 ? { details } : {}),
  };
}

export function productAgentProgressDetails(input: ProductAgentProgressInput): ScanProgressDetail[] {
  const details: ScanProgressDetail[] = [
    {
      id: "phase",
      label: "Phase",
      status: input.status,
      value: productAgentPhaseLabel(input.phase),
    },
  ];

  if (input.taskId || input.taskLabel) {
    details.push({
      id: input.taskId ?? "task",
      label: input.taskLabel ?? "Task",
      status: input.status,
      ...(input.taskId ? { value: input.taskId } : {}),
    });
  }
  if (input.roleId) {
    details.push({
      id: "role",
      label: "Agent role",
      status: input.status,
      value: input.roleId,
    });
  }
  if (input.candidateId) {
    details.push({
      id: "candidate",
      label: "Candidate",
      status: input.status,
      value: input.candidateId,
    });
  }
  if (input.candidateCount !== undefined) {
    details.push({
      id: "candidate-count",
      label: "Candidates",
      status: input.status,
      value: input.totalCandidates !== undefined
        ? `${input.candidateCount}/${input.totalCandidates}`
        : String(input.candidateCount),
    });
  }
  addCountDetail(details, "completed-count", "Completed", input.completedCount, input.status);
  addCountDetail(details, "accepted-count", "Accepted", input.acceptedCount, input.status);
  addCountDetail(details, "rejected-count", "Rejected", input.rejectedCount, input.status);
  addCountDetail(details, "needs-review-count", "Needs review", input.needsReviewCount, input.status);

  if (input.checkpointPath) {
    details.push({
      id: "checkpoint-path",
      label: "Checkpoint path",
      status: input.status,
      value: input.checkpointPath,
    });
  }
  if (input.resume) {
    details.push(...resumeDetails(input.resume));
  }

  return details;
}

function resumeDetails(resume: ProductAgentCheckpointResumeMetadata): ScanProgressDetail[] {
  const status: ScanProgressStatus = resume.available ? "completed" : "skipped";
  const details: ScanProgressDetail[] = [
    {
      id: "resume",
      label: "Resume",
      status,
      value: resume.available ? "available" : resume.reason ?? "missing",
      message: resume.available
        ? `Loaded checkpoint metadata for ${resume.assistMode}.`
        : "No compatible product agent checkpoint was available.",
    },
    {
      id: "resume-candidates",
      label: "Resume candidates",
      status,
      value: String(resume.candidateCount),
    },
  ];
  if (resume.completedTaskIds.length > 0) {
    details.push({
      id: "resume-completed-tasks",
      label: "Completed tasks",
      status,
      value: String(resume.completedTaskIds.length),
    });
  }
  if (resume.lastPhase) {
    details.push({
      id: "resume-last-phase",
      label: "Last phase",
      status,
      value: productAgentPhaseLabel(resume.lastPhase),
    });
  }
  return details;
}

function addCountDetail(
  details: ScanProgressDetail[],
  id: string,
  label: string,
  count: number | undefined,
  status: ScanProgressStatus,
): void {
  if (count === undefined) {
    return;
  }
  details.push({
    id,
    label,
    status,
    value: String(count),
  });
}

function productAgentProgressId(input: ProductAgentProgressInput): string {
  return [
    "product-agent",
    input.phase,
    input.taskId,
    input.candidateId,
    input.roleId,
  ].filter(Boolean).join(":");
}

function productAgentPhaseLabel(phase: ProductAgentProgressPhase): string {
  if (phase === "candidate") return "Candidate collection";
  if (phase === "task") return "Agent task";
  if (phase === "revalidation") return "Candidate revalidation";
  return "Checkpoint";
}

function productAgentPhaseMessage(phase: ProductAgentProgressPhase, status: ScanProgressStatus): string {
  const label = productAgentPhaseLabel(phase);
  if (status === "running") return `${label} is running.`;
  if (status === "completed") return `${label} completed.`;
  if (status === "skipped") return `${label} skipped.`;
  if (status === "failed") return `${label} failed.`;
  return `${label} is waiting.`;
}
