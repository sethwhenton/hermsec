import type { ScanAssistMode, ScanAssistModeInput, ScanProgressEvent } from "../shared/types.js";

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

export function assistModeFrom(value: ScanAssistModeInput | undefined): ScanAssistMode {
  switch (value) {
    case "single-agent":
      return "single-agent";
    case "moa-assisted":
      return "moa-assisted";
    case "scanner-moa-assisted":
      return "scanner-moa-assisted";
    case "deep-assisted":
    case "scanner-model-summary":
    case undefined:
      return "deep-assisted";
  }
}
