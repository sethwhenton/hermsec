const DEFAULT_DIAGNOSTIC_LIMIT = 4_000;
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  /\b(?=[A-Za-z0-9_+/=-]{32,}\b)(?=[A-Za-z0-9_+/=-]*[A-Z])(?=[A-Za-z0-9_+/=-]*[a-z])(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]{32,}\b/g,
];
const AUTHORIZATION_SECRET_PATTERN =
  /(["']?)(authorization)(\1?\s*[:=]\s*)(["']?)(?:bearer\s+)?[^"'\s;,)]+(?:\s+[^"'\s;,)]+)?/giu;
const KEY_VALUE_SECRET_PATTERN =
  /(["']?)(token|secret|api[_-]?key|password|passwd|private[_-]?key|access[_-]?key|client[_-]?secret)(\1?\s*[:=]\s*)(["']?)[^"'\s;,)]+/giu;

export function safeDiagnosticText(
  value: unknown,
  maxChars = DEFAULT_DIAGNOSTIC_LIMIT,
): string {
  let redacted = String(value ?? "")
    .replace(AUTHORIZATION_SECRET_PATTERN, "$1$2$3$4[REDACTED]")
    .replace(KEY_VALUE_SECRET_PATTERN, "$1$2$3$4[REDACTED]");
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, "[REDACTED_SECRET]");
  }
  if (redacted.length <= maxChars) return redacted;
  return `[truncated]\n${redacted.slice(-maxChars)}`;
}
