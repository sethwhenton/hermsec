import type {
  CanonicalScanAssistMode,
  ScanAssistModeInput,
  ScanProgressEvent,
} from "../shared/types.js";
import { resolveScanAssistMode } from "./scanAssistModes.js";

export type ScanProgressCallback = (event: ScanProgressEvent) => void;

export type ScanProgressInput = Omit<ScanProgressEvent, "schemaVersion" | "timestamp" | "message"> & {
  message?: string;
};

export function emitScanProgress(
  onProgress: ScanProgressCallback | undefined,
  event: ScanProgressInput,
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

export function assistModeFrom(
  value: ScanAssistModeInput | undefined,
): CanonicalScanAssistMode {
  return resolveScanAssistMode(value);
}
