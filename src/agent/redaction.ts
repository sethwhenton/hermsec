export type RedactionPurpose = "model" | "report" | "log";

export type RedactionResult<T = unknown> = {
  value: T;
  redacted: boolean;
  markers: string[];
};

const markerByPurpose: Record<RedactionPurpose, string> = {
  model: "[REDACTED_FOR_MODEL]",
  report: "[REDACTED_SECRET]",
  log: "[REDACTED]"
};

const redactionPlaceholders = new Set(Object.values(markerByPurpose));

const quotedAssignmentPattern =
  /((?<![A-Za-z0-9_$-])["']?([A-Za-z_$][A-Za-z0-9_$-]*)["']?\s*[:=]\s*["'`])([^"'`\r\n]+)(["'`])/g;
const unquotedAssignmentPattern =
  /((?<![A-Za-z0-9_$-])(?:export\s+)?([A-Za-z_$][A-Za-z0-9_$-]*)\s*=(?!=|>)\s*)([^\s,;"'`][^\s,;]*)/g;
const typedQuotedAssignmentPattern =
  /((?<![A-Za-z0-9_$-])(?<!\\)(?:(?:(?:export|declare|public|private|protected|readonly|static|abstract|override)\s+)*(?:(?:const|let|var)\s+)?)?([A-Za-z_$][A-Za-z0-9_$-]*)\s*[?!]?\s*:\s*(?=[A-Za-z_$<{\[(])[^=;\r\n,)]{1,200}\s*=\s*["'`])([^"'`\r\n]+)(["'`])/g;
const typedUnquotedAssignmentPattern =
  /((?<![A-Za-z0-9_$-])(?<!\\)(?:(?:(?:export|declare|public|private|protected|readonly|static|abstract|override)\s+)*(?:(?:const|let|var)\s+)?)?([A-Za-z_$][A-Za-z0-9_$-]*)\s*[?!]?\s*:\s*(?=[A-Za-z_$<{\[(])[^=;\r\n,)]{1,200}\s*=(?!=|>)\s*)([^\s,;"'`][^\s,;]*)/g;

const secretPatterns: Array<{ name: string; pattern: RegExp }> = [
  {
    name: "private-key",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
  },
  {
    name: "authorization-header",
    pattern: /(authorization\s*[:=]\s*)(?:bearer\s+)?[A-Za-z0-9._~+/=-]{16,}/gi
  },
  {
    name: "github-token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g
  },
  {
    name: "gitlab-token",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    name: "openai-like-token",
    pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g
  },
  {
    name: "google-api-key",
    pattern: /\bAIza[A-Za-z0-9_-]{30,}\b/g
  },
  {
    name: "slack-token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g
  },
  {
    name: "stripe-key",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g
  },
  {
    name: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    name: "aws-access-key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g
  },
  {
    name: "credential-url",
    pattern: /(\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]*:)[^@\s/]+(@)/gi
  },
  {
    name: "query-credential",
    pattern: /([?&](?:key|api[_-]?key|token|access[_-]?token|auth|authorization|client[_-]?secret|password)=)[^&#\s]+/gi
  },
  {
    name: "fake-test-token",
    pattern: /HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE[A-Za-z0-9_-]*/g
  },
  {
    name: "high-entropy",
    pattern: /\b(?=[A-Za-z0-9_+/=-]{32,}\b)(?=[A-Za-z0-9_+/=-]*[A-Z])(?=[A-Za-z0-9_+/=-]*[a-z])(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]{32,}\b/g
  }
];

export function redactForModel<T = unknown>(input: T): RedactionResult<T> {
  return redactUnknown(input, "model") as RedactionResult<T>;
}

export function redactForReport<T = unknown>(input: T): RedactionResult<T> {
  return redactUnknown(input, "report") as RedactionResult<T>;
}

export function redactForLog<T = unknown>(input: T): RedactionResult<T> {
  return redactUnknown(input, "log") as RedactionResult<T>;
}

export function sanitizeErrorMessage(
  error: unknown,
  fallback = "Provider request failed.",
): string {
  const raw = error instanceof Error
    ? error.message
    : typeof error === "string"
      ? error
      : fallback;
  const redacted = String(redactForLog(raw).value)
    .replace(/[\r\n\t]+/gu, " ")
    .replace(/\s{2,}/gu, " ")
    .trim()
    .slice(0, 500);
  return redacted || fallback;
}

function redactUnknown(input: unknown, purpose: RedactionPurpose): RedactionResult {
  const markers = new Set<string>();
  const marker = markerByPurpose[purpose];
  const seen = new WeakSet<object>();
  const value = visit(input, marker, markers, seen);
  return {
    value,
    redacted: markers.size > 0,
    markers: [...markers].sort()
  };
}

function visit(input: unknown, marker: string, markers: Set<string>, seen: WeakSet<object>): unknown {
  if (typeof input === "string") {
    return redactString(input, marker, markers);
  }
  if (input === null || typeof input !== "object") {
    return input;
  }
  if (seen.has(input)) {
    return "[Circular]";
  }
  seen.add(input);

  if (Array.isArray(input)) {
    return input.map((item) => visit(item, marker, markers, seen));
  }

  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(input)) {
    if (
      isSensitiveKey(key) &&
      typeof value === "string" &&
      value.length > 0 &&
      !isRedactionPlaceholder(value)
    ) {
      markers.add("sensitive-key");
      output[key] = marker;
      continue;
    }
    output[key] = visit(value, marker, markers, seen);
  }
  return output;
}

function redactString(input: string, marker: string, markers: Set<string>): string {
  const escapedAssignments = protectEscapedQuotedAssignments(
    input,
    marker,
    markers,
  );
  let output = escapedAssignments.value.replace(
    typedQuotedAssignmentPattern,
    (match, prefix: string, key: string, value: string, suffix: string) => {
      if (!isSensitiveKey(key) || isRedactionPlaceholder(value)) {
        return match;
      }
      markers.add("sensitive-assignment");
      return `${prefix}${marker}${suffix}`;
    },
  );
  output = output.replace(
    quotedAssignmentPattern,
    (match, prefix: string, key: string, value: string, suffix: string) => {
      if (!isSensitiveKey(key) || isRedactionPlaceholder(value)) {
        return match;
      }
      markers.add("sensitive-assignment");
      return `${prefix}${marker}${suffix}`;
    },
  );
  output = output.replace(
    typedUnquotedAssignmentPattern,
    (match, prefix: string, key: string, value: string) => {
      if (!isSensitiveKey(key) || isRedactionPlaceholder(value)) {
        return match;
      }
      markers.add("sensitive-assignment");
      return `${prefix}${marker}`;
    },
  );
  output = output.replace(
    unquotedAssignmentPattern,
    (match, prefix: string, key: string, value: string) => {
      if (!isSensitiveKey(key) || isRedactionPlaceholder(value)) {
        return match;
      }
      markers.add("sensitive-assignment");
      return `${prefix}${marker}`;
    },
  );
  for (const { name, pattern } of secretPatterns) {
    output = output.replace(pattern, (...args: string[]) => {
      markers.add(name);
      if (name === "authorization-header" || name === "query-credential") {
        return `${args[1] ?? ""}${marker}`;
      }
      if (name === "credential-url") {
        return `${args[1] ?? ""}${marker}${args[2] ?? ""}`;
      }
      return marker;
    });
  }
  return restoreProtectedAssignments(
    output,
    escapedAssignments.protectedValues,
  );
}

function isRedactionPlaceholder(input: string): boolean {
  if (redactionPlaceholders.has(input)) {
    return true;
  }
  const withoutEscapedLeadingWhitespace = input.replace(
    /^(?:(?:\\[nrtfv])|(?:\\u00(?:09|0a|0d|20)))+/giu,
    "",
  );
  return (
    withoutEscapedLeadingWhitespace !== input &&
    redactionPlaceholders.has(withoutEscapedLeadingWhitespace)
  );
}

function protectEscapedQuotedAssignments(
  input: string,
  marker: string,
  markers: Set<string>,
): {
  value: string;
  protectedValues: ReadonlyMap<string, string>;
} {
  const startPattern =
    /(?:(?<![A-Za-z0-9_$-])(?<!\\)(?:(?:(?:export|declare|public|private|protected|readonly|static|abstract|override)\s+)*(?:(?:const|let|var)\s+)?)?([A-Za-z_$][A-Za-z0-9_$-]*)\s*[?!]?\s*:\s*(?=[A-Za-z_$<{\[(])[^=;\r\n,)]{1,200}\s*=|(?<![A-Za-z0-9_$-])["']?([A-Za-z_$][A-Za-z0-9_$-]*)["']?\s*[:=])\s*(?<!\\)\\(["'`])/gu;
  const protectedValues = new Map<string, string>();
  const replacements: Array<{
    start: number;
    end: number;
    token: string;
    value: string;
  }> = [];
  let match: RegExpExecArray | null;
  let tokenIndex = 0;
  while ((match = startPattern.exec(input)) !== null) {
    const key = match[1] ?? match[2];
    const quote = match[3];
    if (!key || !quote || !isSensitiveKey(key)) {
      continue;
    }
    const closingStart = findEscapedClosingQuote(
      input,
      startPattern.lastIndex,
      quote,
    );
    if (closingStart < 0) {
      continue;
    }
    const rawValue = input.slice(startPattern.lastIndex, closingStart);
    const original = input.slice(match.index, closingStart + 2);
    const replacement = isRedactionPlaceholder(rawValue)
      ? original
      : `${match[0]}${marker}\\${quote}`;
    if (replacement !== original) {
      markers.add("sensitive-assignment");
    }
    let token = `\uE000HERMSEC_REDACTION_${tokenIndex}\uE001`;
    while (input.includes(token) || protectedValues.has(token)) {
      tokenIndex += 1;
      token = `\uE000HERMSEC_REDACTION_${tokenIndex}\uE001`;
    }
    tokenIndex += 1;
    protectedValues.set(token, replacement);
    replacements.push({
      start: match.index,
      end: closingStart + 2,
      token,
      value: replacement,
    });
    startPattern.lastIndex = closingStart + 2;
  }
  if (replacements.length === 0) {
    return { value: input, protectedValues };
  }
  let cursor = 0;
  let value = "";
  for (const replacement of replacements) {
    value += input.slice(cursor, replacement.start);
    value += replacement.token;
    cursor = replacement.end;
  }
  value += input.slice(cursor);
  return { value, protectedValues };
}

function findEscapedClosingQuote(
  input: string,
  valueStart: number,
  quote: string,
): number {
  for (let index = valueStart; index < input.length; index += 1) {
    if (input[index] !== quote) {
      continue;
    }
    let backslashes = 0;
    for (
      let cursor = index - 1;
      cursor >= valueStart && input[cursor] === "\\";
      cursor -= 1
    ) {
      backslashes += 1;
    }
    if (backslashes === 1) {
      return index - 1;
    }
  }
  return -1;
}

function restoreProtectedAssignments(
  input: string,
  protectedValues: ReadonlyMap<string, string>,
): string {
  let output = input;
  for (const [token, value] of protectedValues) {
    output = output.split(token).join(value);
  }
  return output;
}

function isSensitiveKey(input: string): boolean {
  const normalized = input
    .replace(/([A-Z]+)([A-Z][a-z])/gu, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replace(/[^A-Za-z0-9]+/gu, "_")
    .replace(/^_+|_+$/gu, "")
    .toLowerCase();
  const terminal = normalized.split("_").at(-1);
  if (
    terminal === "secret" ||
    terminal === "token" ||
    terminal === "password" ||
    terminal === "passwd" ||
    terminal === "pass" ||
    terminal === "pwd" ||
    terminal === "authorization" ||
    terminal === "credential" ||
    terminal === "credentials"
  ) {
    return true;
  }
  return /(?:^|_)(?:api_key|private_key|access_key)$/u.test(normalized);
}
