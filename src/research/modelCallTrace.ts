import type { CanonicalAgentRole } from "../agent/canonicalHarness.js";
import {
  MOA_ROLES,
  type MoaRoleId,
} from "../agent/moaRoles.js";
import { redactForLog } from "../agent/redaction.js";
import {
  ModelProviderRequestError,
  type ModelProviderAdapter,
  type ModelRequest,
  type ModelResponse,
  type ProviderConfig,
} from "../model/provider.js";
import {
  isLiveModelCallFailFastTriggerError,
  meteredRequestFingerprintForRequest,
  meteredRequestFingerprintFromError,
} from "../model/meteredProvider.js";
import type { ResearchExecutionMode } from "./execution.js";
import { canonicalJson, sha256 } from "./integrity.js";
import {
  fingerprintReplayRequest,
  replayReferenceFromResponse,
  type ReplayReference,
} from "./replay.js";

export const MODEL_CALL_TRACE_FILE = "model-calls.json";
export const MODEL_CALL_TRACE_SCHEMA_VERSION = "2.0";
export const MODEL_CALL_TRACE_ROLE_PLAN_VERSION = "2.0";

export type ModelCallTerminalState = "succeeded" | "failed" | "canceled";

export const MODEL_CALL_ERROR_CATEGORIES = Object.freeze([
  "aborted",
  "budget",
  "exact-model-policy",
  "provider-unavailable",
  "rate-limit",
  "replay",
  "timeout",
  "unsafe-request",
  "provider",
  "unknown",
] as const);

export type ModelCallErrorCategory =
  (typeof MODEL_CALL_ERROR_CATEGORIES)[number];

export type ModelCallCassettePolicy =
  | "none"
  | "recorded"
  | "replay";

export type ModelCallProviderError = {
  status?: number;
  errorType?: string;
  providerCode?: string;
};

export type ResearchModelCallTraceEntry = {
  ordinal: number;
  role: CanonicalAgentRole;
  gapFill: boolean;
  provider: string;
  model: string;
  requestFingerprint: string;
  fingerprintSource: "metered-replay" | "pre-metering-rejection";
  terminalState: ModelCallTerminalState;
  responseProvider?: string;
  responseModel?: string;
  errorCategory?: ModelCallErrorCategory;
  providerError?: ModelCallProviderError;
  cassetteReference?: ReplayReference;
};

export type ResearchModelCallTrace = {
  schemaVersion: typeof MODEL_CALL_TRACE_SCHEMA_VERSION;
  runId: string;
  mode: string;
  execution: ResearchExecutionMode;
  cassettePolicy: ModelCallCassettePolicy;
  physical: boolean;
  derivedFrom: readonly string[];
  detectorStatus:
    | "completed"
    | "partial"
    | "degraded"
    | "failed"
    | "canceled"
    | "not-applicable";
  candidateCount: number;
  aggregationDisposition:
    | "not-applicable"
    | "required"
    | "not-required-no-candidates";
  rolePlan: {
    status: "complete" | "unavailable" | "not-applicable";
    requiredSpecialistRoles: readonly (
      | "single-agent-inspector"
      | MoaRoleId
    )[];
  };
  traceCompleteness: "complete" | "incomplete";
  calls: readonly ResearchModelCallTraceEntry[];
  producerValidation: {
    valid: boolean;
    errors: readonly string[];
  };
};

type MutableTraceEntry = Omit<
  ResearchModelCallTraceEntry,
  "terminalState"
> & {
  terminalState: ModelCallTerminalState | "pending";
};

export type ModelCallTraceRecorder = {
  wrapProvider(input: {
    role: CanonicalAgentRole;
    gapFill: boolean;
    provider: ModelProviderAdapter;
    providerConfig: ProviderConfig;
  }): ModelProviderAdapter;
  drain(): Promise<void>;
  finalize(input: {
    physical: boolean;
    derivedFrom?: readonly string[];
    detectorStatus: ResearchModelCallTrace["detectorStatus"];
    candidateCount?: number;
    requiredSpecialistRoles?: readonly CanonicalAgentRole[];
  }): ResearchModelCallTrace;
};

const ALL_MOA_SPECIALIST_ROLES = Object.freeze(
  MOA_ROLES.map((role) => role.id),
);

export function createModelCallTraceRecorder(input: {
  runId: string;
  mode: string;
  execution: ResearchExecutionMode;
  cassettePolicy?: ModelCallCassettePolicy;
  expectedProvider: string;
  modelForRole: (role: CanonicalAgentRole) => string;
}): ModelCallTraceRecorder {
  let nextOrdinal = 1;
  const entries: MutableTraceEntry[] = [];
  const pendingTerminals = new Set<Promise<void>>();

  return {
    wrapProvider(context) {
      const expectedModel = input.modelForRole(context.role);
      const expectedProvider = input.expectedProvider;
      const base = context.provider;
      const adapter: ModelProviderAdapter = {
        id: base.id,
        ...(base.capabilities
          ? {
              capabilities: {
                ...base.capabilities,
                streaming: false,
              },
            }
          : {}),
        listModels(config) {
          return base.listModels(config);
        },
        healthCheck(config) {
          return base.healthCheck(config);
        },
        async complete(
          request: ModelRequest,
          callConfig?: ProviderConfig,
        ): Promise<ModelResponse> {
          const ordinal = nextOrdinal;
          nextOrdinal += 1;
          const requestedModel =
            request.model ?? callConfig?.model ?? context.providerConfig.model;
          const model =
            typeof requestedModel === "string" && requestedModel.trim()
              ? requestedModel
              : "<missing>";
          const provider =
            callConfig?.provider ??
            context.providerConfig.provider ??
            base.id;
          const meteredRequestFingerprint =
            meteredRequestFingerprintForRequest(
              base,
              request,
              callConfig,
            );
          const fingerprint = meteredRequestFingerprint
            ? {
                value: meteredRequestFingerprint,
                source: "metered-replay" as const,
              }
            : traceFingerprint({
                provider,
                model,
                request,
                ordinal,
              });
          const position = entries.length;
          entries.push({
            ordinal,
            role: context.role,
            gapFill: context.gapFill,
            provider,
            model,
            requestFingerprint: fingerprint.value,
            fingerprintSource: fingerprint.source,
            terminalState: "pending",
          });
          const markCanceled = (): void => {
            const entry = entries[position];
            if (entry?.terminalState !== "pending") {
              return;
            }
            entries[position] = {
              ...entry,
              terminalState: "canceled",
              errorCategory: "aborted",
            };
          };
          if (request.signal?.aborted) {
            markCanceled();
          } else {
            request.signal?.addEventListener("abort", markCanceled, {
              once: true,
            });
          }
          let releaseTerminal!: () => void;
          const pendingTerminal = new Promise<void>((resolve) => {
            releaseTerminal = resolve;
          });
          pendingTerminals.add(pendingTerminal);

          try {
            if (
              provider !== expectedProvider ||
              base.id !== expectedProvider ||
              model !== expectedModel ||
              (request.model &&
                callConfig?.model &&
                request.model !== callConfig.model)
            ) {
              throw new Error(
                "Exact provider/model policy rejected the model call.",
              );
            }
            const response = await base.complete(request, callConfig);
            if (
              response.provider !== expectedProvider ||
              response.model !== expectedModel
            ) {
              throw new Error(
                "Exact provider/model policy rejected the model response.",
              );
            }
            const cassetteReference =
              replayReferenceFromResponse(response);
            entries[position] = {
              ...entries[position]!,
              ...(cassetteReference
                ? {
                    requestFingerprint:
                      cassetteReference.requestFingerprint,
                    cassetteReference,
                  }
                : {}),
              terminalState: "succeeded",
              responseProvider: response.provider,
              responseModel: response.model,
            };
            return response;
          } catch (error) {
            const meteredRequestFingerprint =
              meteredRequestFingerprintFromError(error);
            const terminalState = isAbort(error, request.signal)
              ? "canceled" as const
              : "failed" as const;
            const providerError =
              terminalState === "failed"
                ? providerErrorDetails(error)
                : undefined;
            entries[position] = {
              ...entries[position]!,
              ...(meteredRequestFingerprint
                ? {
                    requestFingerprint: meteredRequestFingerprint,
                    fingerprintSource: "metered-replay" as const,
                  }
                : {}),
              terminalState,
              errorCategory: classifyError(
                error,
                request.signal,
                providerError,
              ),
              ...(providerError ? { providerError } : {}),
            };
            throw error;
          } finally {
            request.signal?.removeEventListener("abort", markCanceled);
            releaseTerminal();
            pendingTerminals.delete(pendingTerminal);
          }
        },
        ...(base.estimateCost
          ? {
              estimateCost(request: ModelRequest, config?: ProviderConfig) {
                return base.estimateCost!(request, config);
              },
            }
          : {}),
      };
      return Object.freeze(adapter);
    },
    async drain(): Promise<void> {
      while (pendingTerminals.size > 0) {
        await Promise.all([...pendingTerminals]);
      }
    },
    finalize(finalInput) {
      const candidateCount = finalInput.candidateCount ?? 0;
      const calls = entries
        .map((entry): ResearchModelCallTraceEntry => {
          const { terminalState, ...rest } = entry;
          if (terminalState === "pending") {
            return {
              ...rest,
              terminalState: "failed",
              errorCategory: "unknown",
            };
          }
          return { ...rest, terminalState };
        })
        .sort((left, right) => left.ordinal - right.ordinal);
      const draft: Omit<ResearchModelCallTrace, "producerValidation"> = {
        schemaVersion: MODEL_CALL_TRACE_SCHEMA_VERSION,
        runId: input.runId,
        mode: input.mode,
        execution: input.execution,
        cassettePolicy:
          input.cassettePolicy ??
          (input.execution === "replay" ? "replay" : "none"),
        physical: finalInput.physical,
        derivedFrom: [...(finalInput.derivedFrom ?? [])],
        detectorStatus: finalInput.detectorStatus,
        candidateCount,
        aggregationDisposition: aggregationDisposition(
          input.mode,
          candidateCount,
        ),
        rolePlan: rolePlanFor(
          input.mode,
          finalInput.requiredSpecialistRoles,
        ),
        traceCompleteness: "complete",
        calls,
      };
      const semanticErrors = validateModelCallTraceSemantics(draft);
      draft.traceCompleteness =
        semanticErrors.length === 0 ? "complete" : "incomplete";
      const errors = validateModelCallTrace(draft);
      return Object.freeze({
        ...draft,
        calls: Object.freeze(calls.map((entry) => Object.freeze(entry))),
        derivedFrom: Object.freeze([...draft.derivedFrom]),
        rolePlan: Object.freeze({
          ...draft.rolePlan,
          requiredSpecialistRoles: Object.freeze([
            ...draft.rolePlan.requiredSpecialistRoles,
          ]),
        }),
        producerValidation: Object.freeze({
          valid: errors.length === 0,
          errors: Object.freeze([...errors]),
        }),
      });
    },
  };
}

export function createEmptyModelCallTrace(input: {
  runId: string;
  mode: string;
  execution: ResearchExecutionMode;
  physical: boolean;
  derivedFrom?: readonly string[];
  detectorStatus?: ResearchModelCallTrace["detectorStatus"];
  cassettePolicy?: ModelCallCassettePolicy;
}): ResearchModelCallTrace {
  const draft: Omit<ResearchModelCallTrace, "producerValidation"> = {
    schemaVersion: MODEL_CALL_TRACE_SCHEMA_VERSION,
    runId: input.runId,
    mode: input.mode,
    execution: input.execution,
    cassettePolicy: input.cassettePolicy ?? "none",
    physical: input.physical,
    derivedFrom: [...(input.derivedFrom ?? [])],
    detectorStatus: input.detectorStatus ?? "not-applicable",
    candidateCount: 0,
    aggregationDisposition: "not-applicable",
    rolePlan: rolePlanFor(input.mode),
    traceCompleteness: "complete",
    calls: [],
  };
  const semanticErrors = validateModelCallTraceSemantics(draft);
  draft.traceCompleteness =
    semanticErrors.length === 0 ? "complete" : "incomplete";
  const errors = validateModelCallTrace(draft);
  return {
    ...draft,
    producerValidation: {
      valid: errors.length === 0,
      errors,
    },
  };
}

export function validateModelCallTrace(
  trace: Omit<ResearchModelCallTrace, "producerValidation">,
): string[] {
  const errors = validateModelCallTraceSemantics(trace);
  const expectedCompleteness =
    errors.length === 0 ? "complete" : "incomplete";
  if (
    !["complete", "incomplete"].includes(trace.traceCompleteness) ||
    trace.traceCompleteness !== expectedCompleteness
  ) {
    errors.push("model-call-trace-completeness-invalid");
  }
  return uniqueSorted(errors);
}

function validateModelCallTraceSemantics(
  trace: Omit<ResearchModelCallTrace, "producerValidation">,
): string[] {
  const errors: string[] = [];
  const calls = Array.isArray(trace.calls) ? trace.calls : [];
  const derivedFrom = Array.isArray(trace.derivedFrom)
    ? trace.derivedFrom
    : [];
  if (
    !hasExactKeys(trace, [
      "aggregationDisposition",
      "calls",
      "candidateCount",
      "cassettePolicy",
      "derivedFrom",
      "detectorStatus",
      "execution",
      "mode",
      "physical",
      "rolePlan",
      "runId",
      "schemaVersion",
      "traceCompleteness",
    ]) ||
    trace.schemaVersion !== MODEL_CALL_TRACE_SCHEMA_VERSION ||
    typeof trace.runId !== "string" ||
    !trace.runId.trim() ||
    typeof trace.mode !== "string" ||
    !trace.mode.trim() ||
    !["mock", "replay", "live"].includes(trace.execution) ||
    !["none", "recorded", "replay"].includes(
      trace.cassettePolicy,
    ) ||
    ![
      "completed",
      "partial",
      "degraded",
      "failed",
      "canceled",
      "not-applicable",
    ].includes(trace.detectorStatus) ||
    typeof trace.physical !== "boolean" ||
    !Number.isSafeInteger(trace.candidateCount) ||
    trace.candidateCount < 0 ||
    !Array.isArray(trace.calls) ||
    !Array.isArray(trace.derivedFrom) ||
    derivedFrom.some(
      (entry) => typeof entry !== "string" || !entry.trim(),
    ) ||
    new Set(derivedFrom).size !== derivedFrom.length ||
    !validRolePlanShape(trace.rolePlan)
  ) {
    errors.push("model-call-trace-schema-invalid");
  }
  if (
    trace.aggregationDisposition !==
    aggregationDisposition(trace.mode, trace.candidateCount)
  ) {
    errors.push("model-call-aggregation-disposition-invalid");
  }
  if (!trace.physical) {
    if (trace.cassettePolicy !== "none") {
      errors.push("derived-run-cassette-policy-invalid");
    }
    if (calls.length > 0) {
      errors.push("derived-run-has-physical-model-calls");
    }
    if (derivedFrom.length === 0) {
      errors.push("derived-run-missing-derivation");
    }
    if (
      trace.rolePlan?.status !== "not-applicable" ||
      trace.rolePlan?.requiredSpecialistRoles?.length !== 0
    ) {
      errors.push("derived-run-role-plan-invalid");
    }
    return uniqueSorted(errors);
  }
  if (derivedFrom.length > 0) {
    errors.push("physical-run-declares-derivation");
  }
  const isAgentMode = [
    "single-agent",
    "moa-low",
    "moa-high",
  ].includes(trace.mode);
  if (!isAgentMode && trace.cassettePolicy !== "none") {
    errors.push("non-agent-run-cassette-policy-invalid");
  }
  if (
    trace.cassettePolicy === "replay" &&
    trace.execution !== "replay"
  ) {
    errors.push("replay-cassette-policy-execution-invalid");
  }
  if (
    trace.cassettePolicy === "recorded" &&
    !["mock", "live"].includes(trace.execution)
  ) {
    errors.push("recorded-cassette-policy-execution-invalid");
  }
  if (
    trace.execution === "replay" &&
    isAgentMode &&
    trace.cassettePolicy !== "replay"
  ) {
    errors.push("replay-agent-cassette-policy-missing");
  }
  if (!isAgentMode && calls.length > 0) {
    errors.push("non-agent-run-has-model-calls");
  }
  if (
    !isAgentMode &&
    (trace.rolePlan?.status !== "not-applicable" ||
      trace.rolePlan?.requiredSpecialistRoles?.length !== 0)
  ) {
    errors.push("non-agent-run-role-plan-invalid");
  }
  if (
    isAgentMode &&
    trace.detectorStatus === "completed" &&
    calls.length === 0
  ) {
    errors.push("successful-agent-run-has-zero-model-calls");
  }

  const seenOrdinals = new Set<number>();
  const seenRequestFingerprints = new Set<string>();
  for (const [index, candidate] of calls.entries()) {
    if (!isPlainRecord(candidate)) {
      errors.push("model-call-entry-invalid");
      continue;
    }
    const call = candidate as ResearchModelCallTraceEntry;
    const hasCassetteReference = Object.hasOwn(
      call,
      "cassetteReference",
    );
    const hasProviderError = Object.hasOwn(call, "providerError");
    const expectedKeys =
      call.terminalState === "succeeded"
        ? [
            ...(hasCassetteReference
              ? ["cassetteReference"]
              : []),
            "fingerprintSource",
            "gapFill",
            "model",
            "ordinal",
            "provider",
            "requestFingerprint",
            "responseModel",
            "responseProvider",
            "role",
            "terminalState",
          ]
        : [
            "errorCategory",
            "fingerprintSource",
            "gapFill",
            "model",
            "ordinal",
            "provider",
            ...(hasProviderError ? ["providerError"] : []),
            "requestFingerprint",
            "role",
            "terminalState",
          ];
    if (
      !Number.isSafeInteger(call.ordinal) ||
      call.ordinal !== index + 1 ||
      seenOrdinals.has(call.ordinal)
    ) {
      errors.push("model-call-ordinal-invalid");
    }
    seenOrdinals.add(call.ordinal);
    if (
      !hasExactKeys(call, expectedKeys) ||
      typeof call.gapFill !== "boolean" ||
      call.provider !== "openrouter" ||
      !/^[a-f0-9]{64}$/u.test(call.requestFingerprint) ||
      !["metered-replay", "pre-metering-rejection"].includes(
        call.fingerprintSource,
      ) ||
      !["succeeded", "failed", "canceled"].includes(call.terminalState)
    ) {
      errors.push("model-call-entry-invalid");
    }
    if (seenRequestFingerprints.has(call.requestFingerprint)) {
      errors.push("model-call-request-fingerprint-duplicate");
    }
    seenRequestFingerprints.add(call.requestFingerprint);
    if (
      call.fingerprintSource === "pre-metering-rejection" &&
      call.terminalState !== "failed"
    ) {
      errors.push("pre-metering-rejection-terminal-invalid");
    }
    if (
      call.cassetteReference !== undefined &&
      (!validReplayReference(call.cassetteReference) ||
        call.cassetteReference.requestFingerprint !==
          call.requestFingerprint ||
        !call.cassetteReference.scopeIdSha256 ||
        trace.cassettePolicy === "none" ||
        call.fingerprintSource !== "metered-replay")
    ) {
      errors.push("model-call-cassette-reference-invalid");
    }
    if (
      trace.cassettePolicy !== "none" &&
      call.terminalState === "succeeded" &&
      !call.cassetteReference
    ) {
      errors.push("successful-replay-call-missing-cassette-reference");
    }
    const expectedModel = expectedModelForRole(call.role);
    if (!expectedModel || call.model !== expectedModel) {
      errors.push("model-call-role-model-mismatch");
    }
    if (
      call.terminalState === "succeeded" &&
      (call.responseProvider !== call.provider ||
        call.responseModel !== call.model)
    ) {
      errors.push("model-call-response-binding-mismatch");
    }
    if (
      call.terminalState !== "succeeded" &&
      !MODEL_CALL_ERROR_CATEGORIES.includes(
        call.errorCategory as ModelCallErrorCategory,
      )
    ) {
      errors.push("failed-model-call-error-category-invalid");
    }
    if (
      (call.terminalState === "canceled" &&
        call.errorCategory !== "aborted") ||
      (call.terminalState === "failed" &&
        call.errorCategory === "aborted")
    ) {
      errors.push("model-call-terminal-error-category-mismatch");
    }
    if (
      call.terminalState === "succeeded" &&
      (call.errorCategory !== undefined ||
        call.providerError !== undefined)
    ) {
      errors.push("successful-model-call-has-error");
    }
    if (
      call.terminalState !== "succeeded" &&
      (call.responseProvider !== undefined ||
        call.responseModel !== undefined)
    ) {
      errors.push("failed-model-call-has-response-binding");
    }
    if (call.providerError !== undefined) {
      if (
        call.terminalState !== "failed" ||
        call.fingerprintSource !== "metered-replay" ||
        !validProviderErrorDetails(call.providerError)
      ) {
        errors.push("model-call-provider-error-invalid");
      } else if (
        call.errorCategory !==
        classifyProviderErrorDetails(call.providerError)
      ) {
        errors.push("model-call-provider-error-category-mismatch");
      }
    } else if (
      call.errorCategory === "rate-limit" ||
      call.errorCategory === "provider-unavailable"
    ) {
      errors.push("transient-model-call-missing-provider-error");
    }
  }

  const structuredCalls = calls.filter(
    isPlainRecord,
  ) as unknown as ResearchModelCallTraceEntry[];
  const aggregators = structuredCalls.filter(
    (call) => call.role === "moa-aggregator",
  );
  const judges = structuredCalls.filter(
    (call) => call.role === "moa-judge",
  );
  const specialistCalls = structuredCalls.filter((call) =>
    isMoaSpecialistRole(call.role),
  );
  const minimaxCalls = structuredCalls.filter(
    (call) => call.model === "minimax/minimax-m3",
  );
  if (
    aggregators.some((call) => call.model !== "minimax/minimax-m3") ||
    minimaxCalls.some((call) => call.role !== "moa-aggregator")
  ) {
    errors.push("minimax-aggregator-role-invalid");
  }
  if (aggregators.length > 1 || minimaxCalls.length > 1) {
    errors.push("multiple-moa-aggregator-calls");
  }
  if (
    aggregators.length === 1 &&
    aggregators[0]!.ordinal !== structuredCalls.length
  ) {
    errors.push("moa-aggregator-not-terminal");
  }

  if (trace.mode === "single-agent") {
    if (
      trace.rolePlan?.status !== "complete" ||
      !sameRoles(
        trace.rolePlan.requiredSpecialistRoles,
        ["single-agent-inspector"],
      )
    ) {
      errors.push("single-agent-role-plan-invalid");
    }
    if (
      structuredCalls.some(
        (call) => call.role !== "single-agent-inspector",
      )
    ) {
      errors.push("single-agent-role-invalid");
    }
    if (
      trace.detectorStatus === "completed" &&
      !structuredCalls.some(
        (call) =>
          call.role === "single-agent-inspector" &&
          call.terminalState === "succeeded",
      )
    ) {
      errors.push("successful-single-agent-call-missing");
    }
  } else if (trace.mode === "moa-low" || trace.mode === "moa-high") {
    const requiredRoles =
      trace.rolePlan?.status === "complete"
        ? trace.rolePlan.requiredSpecialistRoles
        : [];
    if (trace.rolePlan?.status !== "complete") {
      errors.push("moa-role-plan-unavailable");
    } else if (
      trace.mode === "moa-low" &&
      (!validMoaRoleSet(requiredRoles) || requiredRoles.length !== 3)
    ) {
      errors.push("moa-low-role-plan-invalid");
    } else if (
      trace.mode === "moa-high" &&
      !sameRoles(requiredRoles, ALL_MOA_SPECIALIST_ROLES)
    ) {
      errors.push("moa-high-role-plan-invalid");
    }
    if (
      structuredCalls.some(
        (call) => call.role === "single-agent-inspector",
      )
    ) {
      errors.push("moa-single-agent-role-invalid");
    }
    if (
      specialistCalls.some(
        (call) =>
          !requiredRoles.includes(
            call.role as MoaRoleId,
          ),
      )
    ) {
      errors.push("moa-unplanned-specialist-call");
    }
    if (
      trace.detectorStatus === "completed" &&
      requiredRoles.some(
        (role) =>
          !specialistCalls.some(
            (call) =>
              call.role === role &&
              call.terminalState === "succeeded",
          ),
      )
    ) {
      errors.push("successful-moa-role-plan-under-provisioned");
    }

    if (trace.candidateCount > 0) {
      if (
        trace.detectorStatus === "completed" &&
        (judges.length !== 1 ||
          judges[0]?.terminalState !== "succeeded")
      ) {
        errors.push("candidate-bearing-moa-judge-incomplete");
      }
      if (
        trace.detectorStatus === "completed" &&
        (aggregators.length !== 1 ||
          aggregators[0]?.terminalState !== "succeeded")
      ) {
        errors.push("candidate-bearing-moa-aggregator-incomplete");
      }
      const judgeOrdinal = judges[0]?.ordinal;
      const aggregatorOrdinal = aggregators[0]?.ordinal;
      const lastSpecialistOrdinal = Math.max(
        0,
        ...specialistCalls.map((call) => call.ordinal),
      );
      if (
        judgeOrdinal !== undefined &&
        judgeOrdinal <= lastSpecialistOrdinal
      ) {
        errors.push("moa-judge-before-specialists-complete");
      }
      if (
        aggregatorOrdinal !== undefined &&
        (aggregatorOrdinal <= (judgeOrdinal ?? 0) ||
          aggregatorOrdinal <= lastSpecialistOrdinal)
      ) {
        errors.push("moa-aggregator-order-invalid");
      }
    } else if (judges.length > 0 || aggregators.length > 0) {
      errors.push("zero-candidate-moa-has-adjudication-calls");
    }
  }
  return uniqueSorted(errors);
}

function validReplayReference(
  value: ReplayReference,
): boolean {
  return (
    isPlainRecord(value) &&
    hasExactKeys(value, [
      "integritySha256",
      "occurrence",
      "relativePath",
      "requestFingerprint",
      "scopeIdSha256",
    ]) &&
    /^[a-f0-9]{64}$/u.test(value.requestFingerprint) &&
    Number.isSafeInteger(value.occurrence) &&
    value.occurrence > 0 &&
    typeof value.relativePath === "string" &&
    /^[a-f0-9]{64}\.[0-9]{6,}\.json$/u.test(value.relativePath) &&
    /^[a-f0-9]{64}$/u.test(value.integritySha256) &&
    (value.scopeIdSha256 === undefined ||
      /^[a-f0-9]{64}$/u.test(value.scopeIdSha256))
  );
}

function traceFingerprint(input: {
  provider: string;
  model: string;
  request: ModelRequest;
  ordinal: number;
}): {
  value: string;
  source: ResearchModelCallTraceEntry["fingerprintSource"];
} {
  try {
    return {
      value: fingerprintReplayRequest(input),
      source: "metered-replay",
    };
  } catch {
    const { signal: _signal, ...requestWithoutSignal } =
      input.request;
    const redacted = redactForLog(requestWithoutSignal);
    return {
      value: sha256(
        canonicalJson({
          provider: input.provider,
          model: input.model,
          rejectedBeforeMetering: true,
          ordinal: input.ordinal,
          redactionMarkers: [...redacted.markers].sort(),
          requestStructure: structuralFingerprintValue(
            redacted.value,
          ),
        }),
      ),
      source: "pre-metering-rejection",
    };
  }
}

function rolePlanFor(
  mode: string,
  roles?: readonly CanonicalAgentRole[],
): ResearchModelCallTrace["rolePlan"] {
  if (mode === "single-agent") {
    return {
      status: "complete",
      requiredSpecialistRoles: ["single-agent-inspector"],
    };
  }
  if (mode === "moa-low" || mode === "moa-high") {
    if (!roles) {
      return {
        status: "unavailable",
        requiredSpecialistRoles: [],
      };
    }
    return {
      status: "complete",
      requiredSpecialistRoles: roles.filter(isMoaSpecialistRole),
    };
  }
  return {
    status: "not-applicable",
    requiredSpecialistRoles: [],
  };
}

function validRolePlanShape(
  value: ResearchModelCallTrace["rolePlan"],
): boolean {
  return (
    isPlainRecord(value) &&
    hasExactKeys(value, [
      "requiredSpecialistRoles",
      "status",
    ]) &&
    ["complete", "unavailable", "not-applicable"].includes(
      value.status,
    ) &&
    Array.isArray(value.requiredSpecialistRoles) &&
    value.requiredSpecialistRoles.every(
      (role) =>
        role === "single-agent-inspector" ||
        isMoaSpecialistRole(role),
    ) &&
    new Set(value.requiredSpecialistRoles).size ===
      value.requiredSpecialistRoles.length
  );
}

function validMoaRoleSet(
  roles: readonly (
    | "single-agent-inspector"
    | MoaRoleId
  )[],
): roles is readonly MoaRoleId[] {
  return (
    roles.every(isMoaSpecialistRole) &&
    new Set(roles).size === roles.length
  );
}

function isMoaSpecialistRole(
  role: CanonicalAgentRole,
): role is MoaRoleId {
  return ALL_MOA_SPECIALIST_ROLES.includes(role as MoaRoleId);
}

function sameRoles(
  actual: readonly (
    | "single-agent-inspector"
    | MoaRoleId
  )[],
  expected: readonly (
    | "single-agent-inspector"
    | MoaRoleId
  )[],
): boolean {
  return (
    actual.length === expected.length &&
    actual.every((role, index) => role === expected[index])
  );
}

function structuralFingerprintValue(value: unknown): unknown {
  if (typeof value === "string") {
    return {
      kind: "string",
      characters: value.length,
      bytes: Buffer.byteLength(value, "utf8"),
      sha256: sha256(value),
    };
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(structuralFingerprintValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => key !== "signal")
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [
          key,
          structuralFingerprintValue(entry),
        ]),
    );
  }
  return { kind: typeof value };
}

function expectedModelForRole(role: CanonicalAgentRole): string | undefined {
  if (role === "moa-aggregator") {
    return "minimax/minimax-m3";
  }
  if (role === "moa-judge") {
    return "xiaomi/mimo-v2.5";
  }
  if (
    role === "single-agent-inspector" ||
    role === "injection-and-execution" ||
    role === "identity-and-request-security" ||
    role === "sensitive-data-and-cryptography" ||
    role === "dependencies-and-supply-chain" ||
    role === "platform-storage-and-deployment"
  ) {
    return "deepseek/deepseek-v4-flash";
  }
  return undefined;
}

function aggregationDisposition(
  mode: string,
  candidateCount: number,
): ResearchModelCallTrace["aggregationDisposition"] {
  if (mode !== "moa-low" && mode !== "moa-high") {
    return "not-applicable";
  }
  return candidateCount > 0 ? "required" : "not-required-no-candidates";
}

function isAbort(error: unknown, signal?: AbortSignal): boolean {
  if (isLiveModelCallFailFastTriggerError(error)) {
    return false;
  }
  if (signal?.aborted === true) {
    return true;
  }
  if (error instanceof ModelProviderRequestError) {
    return false;
  }
  return (
    error instanceof Error &&
    (error.name === "AbortError" || /abort/iu.test(error.message))
  );
}

function classifyError(
  error: unknown,
  signal?: AbortSignal,
  providerError?: ModelCallProviderError,
): ModelCallErrorCategory {
  if (isAbort(error, signal)) {
    return "aborted";
  }
  if (providerError) {
    return classifyProviderErrorDetails(providerError);
  }
  if (error instanceof ModelProviderRequestError) {
    return "provider";
  }
  const name = error instanceof Error ? error.name.toLowerCase() : "";
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error);
  if (/cost|budget|kill switch/iu.test(`${name} ${message}`)) {
    return "budget";
  }
  if (/replay|cassette/iu.test(`${name} ${message}`)) {
    return "replay";
  }
  if (/timeout|timed out/iu.test(`${name} ${message}`)) {
    return "timeout";
  }
  if (
    /redact|secret|unsafe request|content[_-]policy[_-]violation|error_type=refusal/iu.test(
      `${name} ${message}`,
    )
  ) {
    return "unsafe-request";
  }
  if (/exact|fallback|model|provider.*policy/iu.test(`${name} ${message}`)) {
    return "exact-model-policy";
  }
  if (error instanceof Error) {
    return "provider";
  }
  return "unknown";
}

function providerErrorDetails(
  error: unknown,
): ModelCallProviderError | undefined {
  if (!(error instanceof ModelProviderRequestError)) {
    return undefined;
  }
  const details: ModelCallProviderError = {};
  const status = error.status;
  if (
    typeof status === "number" &&
    Number.isSafeInteger(status) &&
    status >= 400 &&
    status <= 599
  ) {
    details.status = status;
  }
  const errorType = normalizedProviderErrorToken(error.errorType);
  if (errorType) {
    details.errorType = errorType;
  }
  const providerCode = normalizedProviderErrorToken(
    error.providerCode,
  );
  if (providerCode) {
    details.providerCode = providerCode;
  }
  return Object.keys(details).length > 0
    ? Object.freeze(details)
    : undefined;
}

function validProviderErrorDetails(
  value: ModelCallProviderError,
): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (
    keys.length === 0 ||
    keys.some(
      (key) =>
        key !== "status" &&
        key !== "errorType" &&
        key !== "providerCode",
    )
  ) {
    return false;
  }
  return (
    (value.status === undefined ||
      (Number.isSafeInteger(value.status) &&
        value.status >= 400 &&
        value.status <= 599)) &&
    (value.errorType === undefined ||
      normalizedProviderErrorToken(value.errorType) ===
        value.errorType) &&
    (value.providerCode === undefined ||
      normalizedProviderErrorToken(value.providerCode) ===
        value.providerCode)
  );
}

function classifyProviderErrorDetails(
  details: ModelCallProviderError,
): ModelCallErrorCategory {
  const status = details.status;
  const errorType = details.errorType;
  if (errorType === "rate_limit_exceeded") {
    return status === undefined || status === 429
      ? "rate-limit"
      : "provider";
  }
  if (
    errorType === "provider_overloaded" ||
    errorType === "provider_unavailable"
  ) {
    const allowedStatuses =
      errorType === "provider_overloaded"
        ? [502, 503, 529]
        : [404, 502, 503, 529];
    return status === undefined || allowedStatuses.includes(status)
      ? "provider-unavailable"
      : "provider";
  }
  if (errorType === "server") {
    return status === undefined || [500, 502, 503].includes(status)
      ? "provider-unavailable"
      : "provider";
  }
  if (errorType === "timeout") {
    return status === undefined || status === 408 || status === 504
      ? "timeout"
      : "provider";
  }
  if (
    errorType === "content_policy_violation" ||
    errorType === "refusal"
  ) {
    return status === undefined || status === 400 || status === 403
      ? "unsafe-request"
      : "provider";
  }
  if (errorType !== undefined) {
    return "provider";
  }
  if (status === 429) {
    return "rate-limit";
  }
  if (status === 502 || status === 503 || status === 529) {
    return "provider-unavailable";
  }
  if (status === 408 || status === 504) {
    return "timeout";
  }
  return "provider";
}

function normalizedProviderErrorToken(
  value: unknown,
): string | undefined {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,99}$/iu.test(value)
  ) {
    return undefined;
  }
  const originalRedaction = redactForLog(value);
  const normalized = value.toLowerCase();
  const normalizedRedaction = redactForLog(normalized);
  return !originalRedaction.redacted &&
    originalRedaction.value === value &&
    !normalizedRedaction.redacted &&
    normalizedRedaction.value === normalized
    ? normalized
    : undefined;
}

function isPlainRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function hasExactKeys(
  value: unknown,
  expected: readonly string[],
): boolean {
  return (
    isPlainRecord(value) &&
    canonicalJson(Object.keys(value).sort()) ===
      canonicalJson([...expected].sort())
  );
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}
