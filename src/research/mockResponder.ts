import type {
  ModelMessage,
  ModelRequest,
  ModelResponse,
  ModelToolCall,
} from "../model/provider.js";

type ToolEvidence = {
  evidenceId: string;
  tool: string;
  data: unknown;
};

type SearchMatch = {
  file: string;
  line: number;
  preview: string;
  evidenceId: string;
};

type MockFindingDefinition = {
  vulnerabilityClass: string;
  title: string;
  category: "code" | "secret";
  severity: "critical" | "high" | "medium" | "low" | "info";
  cwe: string;
  remediation: string;
};

type MockToolStep = {
  name: "list_files" | "search_code";
  arguments: Record<string, unknown>;
};

const singleSequence = [
  { name: "search_code", arguments: { query: "SELECT ", limit: 80 } },
  { name: "search_code", arguments: { query: "exec", limit: 80 } },
  { name: "search_code", arguments: { query: "shell=True", limit: 80 } },
  { name: "search_code", arguments: { query: "<h1>", limit: 80 } },
  { name: "search_code", arguments: { query: "md5", limit: 80 } },
  { name: "search_code", arguments: { query: "fixture_only", limit: 80 } },
  { name: "search_code", arguments: { query: "TOKEN", limit: 80 } },
  { name: "search_code", arguments: { query: "file", limit: 80 } },
] as const;

/**
 * Deterministic model substitute for mock experiments. It drives the same
 * native tool loop as live models and derives candidates only from returned
 * evidence, so it tests orchestration rather than bypassing it with fixtures.
 */
export function createDeterministicResearchMockResponder(): (
  request: ModelRequest,
  context: { provider: string; model: string },
) => ModelResponse {
  return (request, context) => {
    const system = firstMessage(request.messages, "system").toLowerCase();
    if (system.includes("moa evidence judge")) {
      return response(
        context.model,
        JSON.stringify({
          judgments: candidateIds(request).map((candidateId) => ({
            candidateId,
            verdict: "accepted",
            confidence: "high",
            reason:
              "The candidate is bound to repository tool evidence and a source location.",
          })),
        }),
      );
    }
    if (system.includes("moa aggregator")) {
      return response(
        context.model,
        JSON.stringify({
          groups: candidateIds(request).map((candidateId) => ({
            candidateIds: [candidateId],
            rationale:
              "Preserve the known evidence-bound candidate for deterministic fusion.",
          })),
        }),
      );
    }

    const evidence = extractToolEvidence(request.messages);
    const gapFill = isGapFillRequest(request);
    const sequence: readonly MockToolStep[] = gapFill
      ? [{ name: "list_files", arguments: { limit: 500 } }]
      : sequenceForRole(system);
    const maxCallsThisRound = gapFill ? 1 : 2;
    const toolAccessOpen =
      (request.tools?.length ?? 0) > 0 && request.toolChoice !== "none";
    if (toolAccessOpen && evidence.length < sequence.length) {
      const calls = sequence
        .slice(
          evidence.length,
          evidence.length + maxCallsThisRound,
        )
        .map((step, index) =>
          toolCall(
            `mock-tool-${evidence.length + index + 1}`,
            step.name,
            step.arguments,
          ),
        );
      return response(context.model, "", calls);
    }

    const findings = findingsFromEvidence(evidence);
    return response(
      context.model,
      JSON.stringify(
        findings.length > 0
          ? { findings, abstained: false }
          : {
              findings: [],
              abstained: true,
              abstentionReason:
                "The bounded searches did not return sufficient source evidence.",
            },
      ),
    );
  };
}

function isGapFillRequest(request: ModelRequest): boolean {
  const messages = request.messages.map((message) =>
    message.content.toLowerCase(),
  );
  return messages.some(
    (content) =>
      content.includes(
        "perform exactly one additional bounded coverage pass",
      ) || content.includes('"recommendedcoveragefiles"'),
  );
}

function sequenceForRole(
  system: string,
): readonly MockToolStep[] {
  if (system.includes("single bounded investigator")) {
    return singleSequence;
  }
  if (system.includes("injection and execution")) {
    return [
      singleSequence[1],
      singleSequence[2],
      singleSequence[0],
      singleSequence[7],
    ];
  }
  if (system.includes("identity and request security")) {
    return [
      singleSequence[3],
      singleSequence[7],
      singleSequence[0],
      singleSequence[6],
    ];
  }
  if (system.includes("sensitive data and cryptography")) {
    return [
      singleSequence[4],
      singleSequence[5],
      singleSequence[6],
      singleSequence[3],
    ];
  }
  if (system.includes("dependencies and supply-chain")) {
    return [
      {
        name: "search_code",
        arguments: { query: "dependencies", limit: 80 },
      },
      {
        name: "search_code",
        arguments: { query: "scripts", limit: 80 },
      },
      singleSequence[5],
      singleSequence[6],
    ];
  }
  return [
    singleSequence[7],
    singleSequence[6],
    singleSequence[4],
    singleSequence[3],
  ];
}

function findingsFromEvidence(
  evidence: readonly ToolEvidence[],
): Array<Record<string, unknown>> {
  const matches = searchMatches(evidence);
  const findings = new Map<string, Record<string, unknown>>();
  for (const match of matches) {
    const definition = classifyMatch(match.preview);
    if (!definition) {
      continue;
    }
    const key = [
      definition.vulnerabilityClass,
      match.file,
      match.line,
    ].join("\u0000");
    const existing = findings.get(key);
    const evidenceIds = new Set<string>(
      Array.isArray(existing?.evidenceIds)
        ? (existing.evidenceIds as string[])
        : [],
    );
    evidenceIds.add(match.evidenceId);
    findings.set(key, {
      candidateId: stableCandidateId(
        definition.vulnerabilityClass,
        match.file,
        match.line,
      ),
      title: definition.title,
      category: definition.category,
      severity: definition.severity,
      confidence: "high",
      description:
        "A bounded repository search located a security-relevant source construct.",
      evidence: match.preview,
      remediation: definition.remediation,
      ruleId: `hermsec.mock.${definition.vulnerabilityClass}`,
      cwe: [definition.cwe],
      evidenceIds: [...evidenceIds].sort(),
      sourceLocations: [
        {
          file: match.file,
          startLine: match.line,
          endLine: match.line,
        },
      ],
    });
  }
  return [...findings.values()].sort((left, right) =>
    String(left.candidateId).localeCompare(String(right.candidateId)),
  );
}

function classifyMatch(preview: string): MockFindingDefinition | undefined {
  const lower = preview.toLowerCase();
  if (lower.includes("select ") && /(?:\$\{|f["']|["']\s*\+)/u.test(preview)) {
    return {
      vulnerabilityClass: "sql-injection",
      title: "Untrusted input is composed into a SQL query",
      category: "code",
      severity: "high",
      cwe: "CWE-89",
      remediation: "Use parameterized queries and bind untrusted values.",
    };
  }
  if (
    lower.includes("exec(") ||
    lower.includes("shell=true") ||
    lower.includes("subprocess.check_output")
  ) {
    return {
      vulnerabilityClass: "command-injection",
      title: "Untrusted input can reach command execution",
      category: "code",
      severity: "high",
      cwe: "CWE-78",
      remediation:
        "Avoid shell execution and pass validated arguments to a fixed executable.",
    };
  }
  if (
    lower.includes("readfilesync") ||
    lower.includes("with open(file_path")
  ) {
    return {
      vulnerabilityClass: "path-traversal",
      title: "A request-controlled path is read without confinement",
      category: "code",
      severity: "medium",
      cwe: "CWE-22",
      remediation:
        "Resolve against a fixed root and reject paths that escape it.",
    };
  }
  if (
    lower.includes("<h1>") &&
    (lower.includes("${") || lower.includes('f"<') || lower.includes("f'<"))
  ) {
    return {
      vulnerabilityClass: "reflected-xss",
      title: "Untrusted text is returned in HTML without encoding",
      category: "code",
      severity: "medium",
      cwe: "CWE-79",
      remediation:
        "Use context-aware output encoding and avoid interpolating request data into HTML.",
    };
  }
  if (lower.includes("md5")) {
    return {
      vulnerabilityClass: "weak-cryptography",
      title: "MD5 is used for a security-relevant digest",
      category: "code",
      severity: "low",
      cwe: "CWE-328",
      remediation:
        "Use a modern cryptographic hash appropriate to the security purpose.",
    };
  }
  if (
    lower.includes("service_api_key") ||
    lower.includes("fakefixturetoken") ||
    lower.includes("fake_fixture_token") ||
    lower.includes("fixture_only_not_a_real_credential") ||
    lower.includes("hermsec_fake_test_token")
  ) {
    return {
      vulnerabilityClass: "hardcoded-secret",
      title: "A credential-like value is hardcoded in source",
      category: "secret",
      severity: "high",
      cwe: "CWE-798",
      remediation:
        "Move credentials to an approved secret store and rotate exposed values.",
    };
  }
  return undefined;
}

function searchMatches(evidence: readonly ToolEvidence[]): SearchMatch[] {
  const matches: SearchMatch[] = [];
  for (const item of evidence) {
    if (
      item.tool !== "search_code" ||
      !isRecord(item.data) ||
      !Array.isArray(item.data.matches)
    ) {
      continue;
    }
    for (const value of item.data.matches) {
      if (
        !isRecord(value) ||
        typeof value.file !== "string" ||
        !Number.isInteger(value.line) ||
        typeof value.preview !== "string"
      ) {
        continue;
      }
      matches.push({
        file: value.file,
        line: value.line as number,
        preview: value.preview,
        evidenceId: item.evidenceId,
      });
    }
  }
  return matches;
}

function extractToolEvidence(
  messages: readonly ModelMessage[],
): ToolEvidence[] {
  const evidence: ToolEvidence[] = [];
  for (const message of messages) {
    if (message.role !== "tool") {
      continue;
    }
    const match = message.content.match(
      /HERMSEC_UNTRUSTED_REPOSITORY_DATA_BEGIN[\s\S]*?\n(\{[^\n]+\})\nHERMSEC_UNTRUSTED_REPOSITORY_DATA_END/u,
    );
    if (!match?.[1]) {
      continue;
    }
    try {
      const value = JSON.parse(match[1]) as unknown;
      if (
        isRecord(value) &&
        typeof value.evidenceId === "string" &&
        typeof value.tool === "string"
      ) {
        evidence.push({
          evidenceId: value.evidenceId,
          tool: value.tool,
          data: value.data,
        });
      }
    } catch {
      // Invalid tool payloads are ignored; the final answer will abstain.
    }
  }
  return evidence;
}

function candidateIds(request: ModelRequest): string[] {
  return [
    ...new Set(
      request.messages.flatMap((message) =>
        [...message.content.matchAll(/"candidateId"\s*:\s*"([^"]+)"/gu)]
          .map((match) => match[1])
          .filter((value): value is string => Boolean(value)),
      ),
    ),
  ].sort();
}

function firstMessage(
  messages: readonly ModelMessage[],
  role: "system" | "user",
): string {
  const message = messages.find((candidate) => candidate.role === role);
  return message?.content ?? "";
}

function toolCall(
  id: string,
  name: string,
  args: Record<string, unknown>,
): ModelToolCall {
  return {
    id,
    type: "function",
    function: {
      name,
      arguments: JSON.stringify(args),
    },
  };
}

function response(
  model: string,
  content: string,
  toolCalls?: ModelToolCall[],
): ModelResponse {
  return {
    provider: "openrouter",
    model,
    content,
    ...(toolCalls ? { toolCalls } : {}),
    finishReason: toolCalls ? "tool_calls" : "stop",
    usage: {
      provider: "openrouter",
      model,
      promptTokens: 240,
      completionTokens: toolCalls ? 60 : 180,
      totalTokens: toolCalls ? 300 : 420,
      estimatedUsd: 0,
      local: true,
    },
  };
}

function stableCandidateId(
  vulnerabilityClass: string,
  file: string,
  line: number,
): string {
  return `mock-${vulnerabilityClass}-${file.replace(/[^a-z0-9]+/giu, "-").replace(/^-|-$/gu, "").toLowerCase()}-${line}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
