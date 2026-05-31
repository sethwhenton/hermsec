import crypto from "node:crypto";

export function stableId(input: string, prefix = "id"): string {
  const digest = crypto.createHash("sha256").update(input).digest("hex").slice(0, 16);
  return `${prefix}-${digest}`;
}

export function redactSecrets(input: string): string {
  return input
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, "sk-[REDACTED]")
    .replace(/(?<=api[_-]?key["'\s:=]{0,8})[A-Za-z0-9_-]{16,}/gi, "[REDACTED]")
    .replace(/HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE[A-Za-z0-9_-]*/g, "HERMSEC_FAKE_TEST_TOKEN_[REDACTED]");
}

export function clampText(value: string, max = 240): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length > max ? `${compact.slice(0, max - 3)}...` : compact;
}
