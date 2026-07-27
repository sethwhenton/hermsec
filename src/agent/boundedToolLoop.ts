import type { ModelProviderAdapter, ModelRequest, ModelResponse, ModelToolCall, ProviderConfig } from "../model/provider.js";
import { dispatchTool } from "./toolDispatcher.js";
import {
  finalRoundInstruction,
  requireInspectionEvidenceInstruction,
  repairFinalOutputInstruction,
} from "./inspectionPrompt.js";
import { redactForModel } from "./redaction.js";
import { toolDefinitions, type ToolRegistry } from "./toolRegistry.js";
import {
  digestValue,
  errorCodeFor,
  frameToolError,
  isInspectionToolName,
  parseModelToolCall,
  prepareEvidence,
  type AgentToolTrace,
  type ToolLoopLimits,
  type ToolLoopResult,
} from "./toolProtocol.js";
import type { ToolContext } from "./permissions.js";

const HARD_MAX_PROVIDER_ROUNDS = 6;

export const DEFAULT_SINGLE_TOOL_LIMITS: ToolLoopLimits = {
  maxRounds: 5,
  maxToolCalls: 8,
  maxCallsPerRound: 8,
  maxTotalBytes: 80_000,
  maxTotalTokens: 256_000,
  maxRepeatedCallCount: 2,
  maxFinalRepairs: 1,
  timeoutMs: 180_000,
};

export const DEFAULT_SPECIALIST_TOOL_LIMITS: ToolLoopLimits = {
  maxRounds: 3,
  maxToolCalls: 16,
  maxCallsPerRound: 16,
  maxTotalBytes: 48_000,
  maxTotalTokens: 160_000,
  maxRepeatedCallCount: 2,
  maxFinalRepairs: 1,
  timeoutMs: 180_000,
};

export type BoundedToolLoopOptions<T> = {
  provider: ModelProviderAdapter;
  providerConfig?: ProviderConfig;
  request: ModelRequest;
  registry: ToolRegistry;
  context: ToolContext;
  parseFinal(content: string): T;
  limits?: Partial<ToolLoopLimits>;
  finalInstruction?: string;
  repairInstruction?: (errorCode: string) => string;
  requireEvidenceBeforeFinal?: boolean;
  signal?: AbortSignal;
  onTrace?: (trace: AgentToolTrace) => void | Promise<void>;
};

export async function runBoundedInspectionLoop<T>(
  options: BoundedToolLoopOptions<T>,
): Promise<ToolLoopResult<T>> {
  const limits = normalizeLimits(options.limits);
  const definitions = toolDefinitions(options.registry);
  if (options.provider.capabilities?.tools !== true) {
    return emptyResult("failed", "provider-tools-unsupported", [
      `Provider ${options.provider.id} does not declare native tool support.`,
    ]);
  }
  if (options.provider.capabilities?.externalAbort !== true) {
    return emptyResult("failed", "provider-abort-unsupported", [
      `Provider ${options.provider.id} does not declare abortable requests.`,
    ]);
  }
  if (definitions.length === 0) {
    return emptyResult("failed", "inspection-tools-unavailable", [
      "The inspection tool registry is empty.",
    ]);
  }

  const timeoutController = new AbortController();
  const timeout = setTimeout(() => {
    timeoutController.abort(new Error("Bounded inspection loop timed out."));
  }, limits.timeoutMs);

  const externalSignals = [options.signal, options.context.signal].filter(
    (signal): signal is AbortSignal => signal !== undefined,
  );
  const combinedSignal = AbortSignal.any([...externalSignals, timeoutController.signal]);
  const messages = [...options.request.messages];
  const traces: AgentToolTrace[] = [];
  const evidence: ToolLoopResult<T>["evidence"] = [];
  const usages: ToolLoopResult<T>["usages"] = [];
  const limitations = new Set<string>();
  const repeatedCalls = new Map<string, number>();
  const seenCallIds = new Set<string>();
  let rounds = 0;
  let toolCalls = 0;
  let totalBytes = 0;
  let totalTokens = 0;
  let finalRepairs = 0;
  let forceFinal = false;
  let forceEvidenceToolRound = false;
  let partial = false;
  let degraded = false;

  try {
    const maxProviderRounds = Math.min(
      HARD_MAX_PROVIDER_ROUNDS,
      limits.maxRounds + limits.maxFinalRepairs,
    );
    for (let round = 1; round <= maxProviderRounds; round += 1) {
      rounds = round;
      if (combinedSignal.aborted) {
        return finishWithoutOutput(
          isExternalAbort(externalSignals) ? "canceled" : evidence.length > 0 ? "degraded" : "failed",
          isExternalAbort(externalSignals) ? "aborted" : "timeout",
        );
      }

      const hasInspectionEvidence = evidence.some((entry) =>
        entry.qualifiesFinalEvidence && entry.bytes > 0
      );
      const needsInspectionEvidence =
        options.requireEvidenceBeforeFinal === true &&
        !hasInspectionEvidence;
      const evidenceRecoveryRound =
        (
          forceEvidenceToolRound ||
          (
            needsInspectionEvidence &&
            round >= limits.maxRounds &&
            round < maxProviderRounds
          )
        ) &&
        !forceFinal &&
        toolCalls < limits.maxToolCalls &&
        totalBytes < limits.maxTotalBytes;
      forceEvidenceToolRound = false;
      const finalOnly =
        !evidenceRecoveryRound &&
        (
          forceFinal ||
          round >= limits.maxRounds ||
          toolCalls >= limits.maxToolCalls ||
          totalBytes >= limits.maxTotalBytes
        );
      const roundMessages = [...messages];
      if (finalOnly) {
        roundMessages.push({
          role: "user",
          content: options.finalInstruction ?? finalRoundInstruction(),
        });
      } else if (needsInspectionEvidence && evidence.length > 0) {
        roundMessages.push({
          role: "user",
          content: requireInspectionEvidenceInstruction(),
        });
      }

      const request: ModelRequest = {
        ...options.request,
        messages: roundMessages,
        requireExactModel: true,
        ...(finalOnly
          ? { tools: [], toolChoice: "none" as const }
          : {
              tools: definitions,
              toolChoice: needsInspectionEvidence
                ? "required" as const
                : "auto" as const,
            }),
        signal: combinedSignal,
      };
      const requestTokenReservation = requestTokenUpperBound(request);
      if (
        totalTokens + requestTokenReservation >
        limits.maxTotalTokens
      ) {
        limitations.add("total-token-limit");
        return finishWithoutOutput(
          evidence.length > 0 ? "partial" : "failed",
          "token-limit",
        );
      }

      let response: ModelResponse;
      try {
        response = await withAbort(
          options.provider.complete(request, options.providerConfig),
          combinedSignal,
        );
      } catch (error) {
        if (combinedSignal.aborted) {
          return finishWithoutOutput(
            isExternalAbort(externalSignals) ? "canceled" : evidence.length > 0 ? "degraded" : "failed",
            isExternalAbort(externalSignals) ? "aborted" : "timeout",
          );
        }
        limitations.add("provider-request-failed");
        return finishWithoutOutput(evidence.length > 0 ? "degraded" : "failed", "provider-error");
      }
      if (response.usage) {
        usages.push(response.usage);
      }
      totalTokens +=
        usageTokenCount(response.usage) ??
        requestTokenReservation;
      if (totalTokens > limits.maxTotalTokens) {
        limitations.add("total-token-limit");
        return finishWithoutOutput(
          evidence.length > 0 ? "degraded" : "failed",
          "token-limit",
        );
      }

      const responseToolCalls = (response.toolCalls ?? []).slice(0, 32);
      if ((response.toolCalls?.length ?? 0) > responseToolCalls.length) {
        degraded = true;
        limitations.add("provider-returned-excessive-tool-calls");
      }
      if (responseToolCalls.length > 0) {
        if (finalOnly) {
          degraded = true;
          limitations.add("tool-call-returned-after-tool-access-closed");
          for (const [index, call] of responseToolCalls.entries()) {
            await recordRejectedCall(call, round, index, "tool-access-closed");
          }
          return finishWithoutOutput(evidence.length > 0 ? "degraded" : "failed", "tool-call-in-final-round");
        }

        messages.push({
          role: "assistant",
          content: redactContent(response.content),
          toolCalls: responseToolCalls.map((call, index) => sanitizeToolCallForHistory(call, round, index)),
        });

        for (let index = 0; index < responseToolCalls.length; index += 1) {
          const rawCall = responseToolCalls[index];
          if (!rawCall) {
            continue;
          }
          if (index >= limits.maxCallsPerRound) {
            degraded = true;
            forceFinal = true;
            limitations.add("per-round-tool-call-limit");
            await recordRejectedCall(rawCall, round, index, "per-round-call-limit");
            continue;
          }
          if (toolCalls >= limits.maxToolCalls) {
            partial = true;
            forceFinal = true;
            limitations.add("total-tool-call-limit");
            await recordRejectedCall(rawCall, round, index, "total-call-limit");
            continue;
          }

          toolCalls += 1;
          const startedAt = Date.now();
          let parsed;
          try {
            parsed = parseModelToolCall(rawCall);
          } catch (error) {
            degraded = true;
            limitations.add("invalid-tool-call");
            await appendTrace({
              callId: safeCallId(rawCall.id, round, index),
              name: safeTraceName(rawCall.function.name),
              round,
              status: "rejected",
              inputDigest: digestValue({
                name: rawCall.function.name,
                arguments: redactContent(rawCall.function.arguments),
              }),
              bytes: 0,
              durationMs: Date.now() - startedAt,
              redactionMarkers: [],
              truncated: false,
              qualifiesFinalEvidence: false,
              errorCode: errorCodeFor(error),
            });
            messages.push({
              role: "tool",
              toolCallId: safeCallId(rawCall.id, round, index),
              content: frameToolError({
                callId: safeCallId(rawCall.id, round, index),
                toolName: safeTraceName(rawCall.function.name),
                errorCode: errorCodeFor(error),
              }),
            });
            continue;
          }

          if (seenCallIds.has(parsed.id)) {
            degraded = true;
            forceFinal = true;
            limitations.add("duplicate-tool-call-id");
            await rejectParsedCall(parsed, round, startedAt, "duplicate-call-id");
            continue;
          }
          seenCallIds.add(parsed.id);

          const repeated = (repeatedCalls.get(parsed.inputDigest) ?? 0) + 1;
          repeatedCalls.set(parsed.inputDigest, repeated);
          if (repeated > limits.maxRepeatedCallCount) {
            degraded = true;
            forceFinal = true;
            limitations.add("repeated-tool-call-loop");
            await rejectParsedCall(parsed, round, startedAt, "repeated-call-limit");
            continue;
          }

          try {
            const dispatched = await withAbort(
              dispatchTool(options.registry, parsed.name, parsed.input, {
                ...options.context,
                signal: combinedSignal,
              }),
              combinedSignal,
            );
            const remainingBytes = Math.max(0, limits.maxTotalBytes - totalBytes);
            const prepared = prepareEvidence({
              call: parsed,
              toolName: dispatched.name,
              output: dispatched.output,
              maxBytes: remainingBytes,
              redactionMarkers: dispatched.redactionMarkers,
              qualifiesFinalEvidence: dispatched.qualifiesFinalEvidence,
            });
            evidence.push(prepared.evidence);
            totalBytes += prepared.evidence.bytes;
            if (prepared.evidence.truncated) {
              partial = true;
              forceFinal = true;
              limitations.add("tool-output-byte-limit");
            }
            await appendTrace({
              callId: parsed.id,
              evidenceId: prepared.evidence.id,
              name: dispatched.name,
              round,
              status: "completed",
              inputDigest: parsed.inputDigest,
              outputDigest: prepared.evidence.outputDigest,
              bytes: prepared.evidence.bytes,
              durationMs: Date.now() - startedAt,
              redactionMarkers: prepared.evidence.redactionMarkers,
              truncated: prepared.evidence.truncated,
              qualifiesFinalEvidence:
                prepared.evidence.qualifiesFinalEvidence,
            });
            messages.push({
              role: "tool",
              toolCallId: parsed.id,
              name: dispatched.name,
              content: prepared.framedContent,
            });
          } catch (error) {
            const errorCode = combinedSignal.aborted ? "aborted" : errorCodeFor(error);
            if (errorCode === "aborted") {
              await appendTrace({
                callId: parsed.id,
                name: safeTraceName(parsed.name),
                round,
                status: "canceled",
                inputDigest: parsed.inputDigest,
                bytes: 0,
                durationMs: Date.now() - startedAt,
                redactionMarkers: [],
                truncated: false,
                qualifiesFinalEvidence: false,
                errorCode,
              });
              return finishWithoutOutput(
                isExternalAbort(externalSignals) ? "canceled" : evidence.length > 0 ? "degraded" : "failed",
                isExternalAbort(externalSignals) ? "aborted" : "timeout",
              );
            }
            degraded = true;
            limitations.add(errorCode);
            await appendTrace({
              callId: parsed.id,
              name: safeTraceName(parsed.name),
              round,
              status: "failed",
              inputDigest: parsed.inputDigest,
              bytes: 0,
              durationMs: Date.now() - startedAt,
              redactionMarkers: [],
              truncated: false,
              qualifiesFinalEvidence: false,
              errorCode,
            });
            messages.push({
              role: "tool",
              toolCallId: parsed.id,
              content: frameToolError({
                callId: parsed.id,
                toolName: safeTraceName(parsed.name),
                errorCode,
              }),
            });
          }
        }
        continue;
      }

      const finalContent = redactContent(response.content).trim();
      if (!finalContent) {
        degraded = true;
        limitations.add("empty-model-response");
        return finishWithoutOutput(evidence.length > 0 ? "degraded" : "failed", "empty-response");
      }
      if (needsInspectionEvidence) {
        const hasFutureToolRound =
          !finalOnly &&
          round + 1 < maxProviderRounds &&
          toolCalls < limits.maxToolCalls &&
          totalBytes < limits.maxTotalBytes;
        if (hasFutureToolRound) {
          limitations.add("premature-final-before-evidence");
          forceEvidenceToolRound = true;
          messages.push({ role: "assistant", content: finalContent });
          messages.push({
            role: "user",
            content: requireInspectionEvidenceInstruction(),
          });
          continue;
        }
        limitations.add("inspection-evidence-required");
        return finishWithoutOutput("failed", "inspection-evidence-required");
      }

      try {
        const output = options.parseFinal(finalContent);
        return {
          status: degraded ? "degraded" : partial ? "partial" : "completed",
          stopReason: degraded || partial ? "completed-with-limitations" : "final-output",
          rounds,
          toolCalls,
          bytes: totalBytes,
          tokens: totalTokens,
          traces,
          evidence,
          usages,
          limitations: [...limitations],
          output,
          finalContent,
        };
      } catch (error) {
        if (
          finalRepairs < limits.maxFinalRepairs &&
          round < maxProviderRounds
        ) {
          finalRepairs += 1;
          limitations.add("final-output-repair-used");
          forceFinal = true;
          messages.push({ role: "assistant", content: finalContent });
          messages.push({
            role: "user",
            content: (options.repairInstruction ?? repairFinalOutputInstruction)(
              finalOutputErrorCode(error),
            ),
          });
          continue;
        }
        limitations.add("invalid-final-output");
        return {
          status: evidence.length > 0 ? "degraded" : "failed",
          stopReason: "invalid-final-output",
          rounds,
          toolCalls,
          bytes: totalBytes,
          tokens: totalTokens,
          traces,
          evidence,
          usages,
          limitations: [...limitations],
          finalContent,
        };
      }
    }

    return finishWithoutOutput(evidence.length > 0 ? "partial" : "failed", "round-limit");
  } finally {
    clearTimeout(timeout);
  }

  async function recordRejectedCall(
    call: ModelToolCall,
    round: number,
    index: number,
    errorCode: string,
  ): Promise<void> {
    const callId = safeCallId(call.id, round, index);
    const inputDigest = digestValue({
      name: call.function.name,
      arguments: redactContent(call.function.arguments),
    });
    await appendTrace({
      callId,
      name: safeTraceName(call.function.name),
      round,
      status: "rejected",
      inputDigest,
      bytes: 0,
      durationMs: 0,
      redactionMarkers: [],
      truncated: false,
      qualifiesFinalEvidence: false,
      errorCode,
    });
    messages.push({
      role: "tool",
      toolCallId: callId,
      content: frameToolError({
        callId,
        toolName: safeTraceName(call.function.name),
        errorCode,
      }),
    });
  }

  async function rejectParsedCall(
    parsed: ReturnType<typeof parseModelToolCall>,
    round: number,
    startedAt: number,
    errorCode: string,
  ): Promise<void> {
    await appendTrace({
      callId: parsed.id,
      name: safeTraceName(parsed.name),
      round,
      status: "rejected",
      inputDigest: parsed.inputDigest,
      bytes: 0,
      durationMs: Date.now() - startedAt,
      redactionMarkers: [],
      truncated: false,
      qualifiesFinalEvidence: false,
      errorCode,
    });
    messages.push({
      role: "tool",
      toolCallId: parsed.id,
      content: frameToolError({
        callId: parsed.id,
        toolName: safeTraceName(parsed.name),
        errorCode,
      }),
    });
  }

  async function appendTrace(trace: AgentToolTrace): Promise<void> {
    traces.push(trace);
    if (!options.onTrace) {
      return;
    }
    try {
      await withAbort(Promise.resolve().then(() => options.onTrace?.(trace)), combinedSignal);
    } catch {
      degraded = true;
      limitations.add(combinedSignal.aborted ? "trace-sink-aborted" : "trace-sink-failed");
    }
  }

  function finishWithoutOutput(
    status: ToolLoopResult<T>["status"],
    stopReason: string,
  ): ToolLoopResult<T> {
    return {
      status,
      stopReason,
      rounds,
      toolCalls,
      bytes: totalBytes,
      tokens: totalTokens,
      traces,
      evidence,
      usages,
      limitations: [...limitations],
    };
  }
}

function finalOutputErrorCode(error: unknown): string {
  if (
    error instanceof Error &&
    /^[a-z][a-z0-9-]{0,79}$/u.test(error.message)
  ) {
    return error.message;
  }
  return "invalid-structured-output";
}

function normalizeLimits(input: Partial<ToolLoopLimits> | undefined): ToolLoopLimits {
  return {
    maxRounds: boundedInt(
      input?.maxRounds,
      DEFAULT_SINGLE_TOOL_LIMITS.maxRounds,
      1,
      HARD_MAX_PROVIDER_ROUNDS,
    ),
    maxToolCalls: boundedInt(input?.maxToolCalls, DEFAULT_SINGLE_TOOL_LIMITS.maxToolCalls, 0, 40),
    maxCallsPerRound: boundedInt(input?.maxCallsPerRound, DEFAULT_SINGLE_TOOL_LIMITS.maxCallsPerRound, 1, 16),
    maxTotalBytes: boundedInt(input?.maxTotalBytes, DEFAULT_SINGLE_TOOL_LIMITS.maxTotalBytes, 0, 1_000_000),
    maxTotalTokens: boundedInt(
      input?.maxTotalTokens,
      DEFAULT_SINGLE_TOOL_LIMITS.maxTotalTokens,
      1,
      2_000_000,
    ),
    maxRepeatedCallCount: boundedInt(
      input?.maxRepeatedCallCount,
      DEFAULT_SINGLE_TOOL_LIMITS.maxRepeatedCallCount,
      1,
      5,
    ),
    maxFinalRepairs: boundedInt(input?.maxFinalRepairs, DEFAULT_SINGLE_TOOL_LIMITS.maxFinalRepairs, 0, 1),
    timeoutMs: boundedInt(input?.timeoutMs, DEFAULT_SINGLE_TOOL_LIMITS.timeoutMs, 100, 600_000),
  };
}

function emptyResult<T>(
  status: ToolLoopResult<T>["status"],
  stopReason: string,
  limitations: string[],
): ToolLoopResult<T> {
  return {
    status,
    stopReason,
    rounds: 0,
    toolCalls: 0,
    bytes: 0,
    tokens: 0,
    traces: [],
    evidence: [],
    usages: [],
    limitations,
  };
}

function sanitizeToolCallForHistory(call: ModelToolCall, round: number, index: number): ModelToolCall {
  const name = /^[A-Za-z0-9_.:-]{1,120}$/u.test(call.function.name.trim())
    ? call.function.name.trim()
    : "unknown_tool";
  return {
    id: safeCallId(call.id, round, index),
    type: "function",
    function: {
      name,
      arguments: redactContent(call.function.arguments.slice(0, 20_000)),
    },
  };
}

function safeCallId(value: string, round: number, index: number): string {
  const trimmed = value.trim();
  return /^[A-Za-z0-9_.:-]{1,160}$/u.test(trimmed)
    ? trimmed
    : `rejected-${round}-${index + 1}`;
}

function safeTraceName(value: string): string {
  return isInspectionToolName(value) ? value : "unknown";
}

function redactContent(value: string): string {
  return String(redactForModel(value).value);
}

function isExternalAbort(signals: readonly AbortSignal[]): boolean {
  return signals.some((signal) => signal.aborted);
}

async function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Operation was aborted.");
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(signal.reason instanceof Error ? signal.reason : new Error("Operation was aborted."));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function boundedInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function requestTokenUpperBound(request: ModelRequest): number {
  const promptBytes = Buffer.byteLength(
    JSON.stringify({
      messages: request.messages,
      tools: request.tools ?? [],
      toolChoice: request.toolChoice,
      responseFormat: request.responseFormat,
    }),
    "utf8",
  );
  return promptBytes + Math.max(0, request.maxTokens ?? 0);
}

function usageTokenCount(
  usage: ModelResponse["usage"],
): number | undefined {
  if (!usage) return undefined;
  if (
    Number.isSafeInteger(usage.totalTokens) &&
    (usage.totalTokens ?? -1) >= 0
  ) {
    return usage.totalTokens;
  }
  if (
    Number.isSafeInteger(usage.promptTokens) &&
    Number.isSafeInteger(usage.completionTokens) &&
    (usage.promptTokens ?? -1) >= 0 &&
    (usage.completionTokens ?? -1) >= 0
  ) {
    return (usage.promptTokens ?? 0) + (usage.completionTokens ?? 0);
  }
  return undefined;
}
