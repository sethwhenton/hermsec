export type SecretScanIssue = {
  path: string;
  reason: string;
};

const forbiddenSecretKeyPattern =
  /^(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|private[_-]?key|ssh[_-]?key|pat|bearer|authorization)$/i;

const credentialReferencePathPattern = /(^|\.)providerCredentialRef\.name$|(^|\.)credentialRef\.name$/;

const secretValuePatterns: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g,
  /\bsk-[A-Za-z0-9_-]{12,}\b/g,
  /\bnpm_[A-Za-z0-9]{24,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bHERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE[A-Za-z0-9_-]*\b/g,
];

export function redactSecretText(input: string): string {
  let output = input;
  for (const pattern of secretValuePatterns) {
    output = output.replace(pattern, "[REDACTED]");
  }

  output = output.replace(
    /((?:api[_-]?key|access[_-]?token|password|secret|authorization)["'\s:=]+)([A-Za-z0-9_./+=-]{12,})/gi,
    "$1[REDACTED]",
  );

  return output;
}

export function findSecretIssues(value: unknown, path = "$"): SecretScanIssue[] {
  const issues: SecretScanIssue[] = [];

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      issues.push(...findSecretIssues(item, `${path}[${index}]`));
    });
    return issues;
  }

  if (!value || typeof value !== "object") {
    return issues;
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = `${path}.${key}`;
    if (
      forbiddenSecretKeyPattern.test(key) &&
      !credentialReferencePathPattern.test(childPath)
    ) {
      issues.push({
        path: childPath,
        reason: "secret-like key names are not allowed in persisted Hermsec JSON",
      });
    }

    issues.push(...findSecretIssues(child, childPath));
  }

  return issues;
}

export function assertNoSecretFields(value: unknown): void {
  const issues = findSecretIssues(value);
  if (issues.length > 0) {
    const detail = issues.map((issue) => `${issue.path}: ${issue.reason}`).join("; ");
    throw new Error(`Refusing to persist secret-like data: ${detail}`);
  }
}

export function redactJsonForStorage<T>(value: T, path = "$"): T {
  if (typeof value === "string") {
    if (credentialReferencePathPattern.test(path)) {
      return value;
    }
    return redactSecretText(value) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      redactJsonForStorage(item, `${path}[${index}]`),
    ) as T;
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    output[key] = redactJsonForStorage(child, `${path}.${key}`);
  }

  return output as T;
}

export function sanitizeJsonForWrite<T>(value: T): T {
  assertNoSecretFields(value);
  return redactJsonForStorage(value);
}
