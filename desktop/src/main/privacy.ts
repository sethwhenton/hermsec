import { homedir } from "node:os";
import path from "node:path";

const secretPatterns: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  /\b(?=[A-Za-z0-9_+/=-]{32,}\b)(?=[A-Za-z0-9_+/=-]*[A-Z])(?=[A-Za-z0-9_+/=-]*[a-z])(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]{32,}\b/g,
];

const authorizationSecretPattern =
  /(["']?)(authorization)(\1?\s*[:=]\s*)(["']?)(?:bearer\s+)?[^"'\s;,)]+(?:\s+[^"'\s;,)]+)?/giu;

const keyValueSecretPattern =
  /(["']?)(token|secret|api[_-]?key|password|passwd|private[_-]?key|access[_-]?key|client[_-]?secret)(\1?\s*[:=]\s*)(["']?)[^"'\s;,)]+/giu;

export function redactPrivacyText(value: string, projectRoot?: string): string {
  let output = redactSecretText(value);
  output = replacePathPrefix(output, projectRoot, "[PROJECT]");
  output = replacePathPrefix(output, safeHomeDir(), "[HOME]");
  output = output.replace(/\b[A-Za-z]:[\\/][^\s"'`<>|]+/g, "[LOCAL_PATH]");
  output = output.replace(/\/(?:Users|home)\/[^\s"'`<>|]+/g, "[LOCAL_PATH]");
  output = output.replace(/\bUsers[\\/][^\\/:\s"'`<>|]+/gi, "Users\\[USER]");
  return output;
}

export function redactPrivacyValue<T>(value: T, projectRoot?: string): T {
  if (typeof value === "string") {
    return redactPrivacyText(value, projectRoot) as T;
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactPrivacyValue(item, projectRoot)) as T;
  }

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    output[key] = redactPrivacyValue(child, projectRoot);
  }
  return output as T;
}

export function redactSecretText(value: string): string {
  let output = value
    .replace(authorizationSecretPattern, "$1$2$3$4[REDACTED]")
    .replace(keyValueSecretPattern, "$1$2$3$4[REDACTED]");

  for (const pattern of secretPatterns) {
    output = output.replace(pattern, "[REDACTED_SECRET]");
  }

  return output;
}

function safeHomeDir(): string | undefined {
  try {
    return homedir();
  } catch {
    return undefined;
  }
}

function replacePathPrefix(value: string, prefix: string | undefined, marker: string): string {
  if (!prefix?.trim()) return value;
  const resolved = path.resolve(prefix);
  const patterns = new Set([
    pathPrefixPattern(resolved),
    pathPrefixPattern(resolved.replace(/\\/g, "/")),
  ]);

  let output = value;
  for (const pattern of patterns) {
    if (!pattern) continue;
    output = output.replace(new RegExp(pattern, "gi"), marker);
  }
  return output;
}

function pathPrefixPattern(value: string): string {
  const parts = value.split(/[\\/]+/u).filter(Boolean);
  if (parts.length === 0) return "";
  return parts.map(escapeRegex).join("[\\\\/]");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
