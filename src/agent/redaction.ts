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

const sensitiveKeyPattern = /(?:secret|token|password|passwd|authorization|private[_-]?key|client[_-]?secret|access[_-]?key|api[_-]?key)$/i;

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
    name: "aws-access-key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g
  },
  {
    name: "env-assignment",
    pattern: /^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*).+$/gim
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

  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (sensitiveKeyPattern.test(key) && typeof value === "string" && value.length > 0) {
      markers.add("sensitive-key");
      output[key] = marker;
      continue;
    }
    output[key] = visit(value, marker, markers, seen);
  }
  return output;
}

function redactString(input: string, marker: string, markers: Set<string>): string {
  let output = input;
  for (const { name, pattern } of secretPatterns) {
    output = output.replace(pattern, (...args: string[]) => {
      markers.add(name);
      if (name === "authorization-header" || name === "env-assignment") {
        return `${args[1] ?? ""}${marker}`;
      }
      return marker;
    });
  }
  return output;
}
