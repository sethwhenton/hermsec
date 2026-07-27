export function runIdsMatch(activeRunId: string | null | undefined, candidateRunId: string | null | undefined): boolean {
  return Boolean(activeRunId && candidateRunId && activeRunId === candidateRunId);
}

export function shouldAcceptRunEvent(
  activeRunId: string | null | undefined,
  terminalRunId: string | null | undefined,
  eventRunId: string | null | undefined,
): boolean {
  return runIdsMatch(activeRunId, eventRunId) && terminalRunId !== eventRunId;
}

export function shouldApplyRunCompletion(
  activeRunId: string | null | undefined,
  completedRunId: string | null | undefined,
): boolean {
  return runIdsMatch(activeRunId, completedRunId);
}
