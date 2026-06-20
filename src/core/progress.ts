import type { ScanAssistMode, ScanProgressEvent } from "../shared/types.js";

export type ScanProgressCallback = (event: ScanProgressEvent) => void;

type ProgressInput = Omit<ScanProgressEvent, "schemaVersion" | "timestamp" | "message"> & {
  message?: string;
};

export function emitScanProgress(
  onProgress: ScanProgressCallback | undefined,
  event: ProgressInput,
): void {
  if (!onProgress) {
    return;
  }
  const message = event.message ?? event.label;
  onProgress({
    ...event,
    schemaVersion: "1.0",
    timestamp: new Date().toISOString(),
    message,
  });
}

export function assistModeFrom(value: ScanAssistMode | undefined): ScanAssistMode {
  return value === "deep-assisted" ? "deep-assisted" : "scanner-model-summary";
}
