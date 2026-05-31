import type { OutputFormat, ScanMode } from "../shared/types.js";

export function parseScanMode(value: string | undefined): ScanMode | undefined {
  if (value === undefined) {
    return "auto";
  }
  if (value === "auto" || value === "offline" || value === "online") {
    return value;
  }
  return undefined;
}

export function isScanMode(value: string): value is ScanMode {
  return value === "auto" || value === "offline" || value === "online";
}

export function selectedFormats(flags: { json?: unknown; md?: unknown; html?: unknown }): OutputFormat[] {
  const formats: OutputFormat[] = [];
  if (flags.json === true) {
    formats.push("json");
  }
  if (flags.md === true) {
    formats.push("md");
  }
  if (flags.html === true) {
    formats.push("html");
  }
  return formats.length > 0 ? formats : ["json", "md", "html"];
}

export function isDailyTime(value: string): boolean {
  if (!/^\d{2}:\d{2}$/.test(value)) {
    return false;
  }
  const [hourText, minuteText] = value.split(":");
  const hour = Number(hourText);
  const minute = Number(minuteText);
  return Number.isInteger(hour) && Number.isInteger(minute) && hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}

export function isDuration(value: string): boolean {
  return /^\d+(ms|s|m|h)$/.test(value);
}

export function looksLikeSecretKey(key: string): boolean {
  return /(?:api[_-]?key|token|secret|password|credential|private[_-]?key)/i.test(key);
}
