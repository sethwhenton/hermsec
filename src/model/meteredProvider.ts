import {
  calculateActualCostNanoUsd,
  calculateWorstCaseCostNanoUsd,
  CostKillSwitchError,
  CostLedger,
  estimatePromptTokenUpperBound,
  nanoUsdToUsd,
  usdToNanoUsd,
  type CostReconciliation,
} from "../agent/costTracker.js";
import {
  requireExactAllowedModel,
  snapshotExecutionPolicy,
  validateExecutionPolicy,
  validateModeBudget,
  type ResearchExecutionPolicy,
} from "../research/execution.js";
import {
  requireModelPrice,
  validatePricingCatalogForLive,
  type LivePricingValidationOptions,
  type PricingCatalog,
} from "../research/pricing.js";
import {
  attachReplayReference,
  fingerprintReplayRequest,
  ReplayCassetteStore,
} from "../research/replay.js";
import type {
  CostEstimate,
  ModelProviderAdapter,
  ModelRequest,
  ModelResponse,
  ProviderConfig,
} from "./provider.js";

export type MockModelResponder = (
  request: ModelRequest,
  context: { provider: string; model: string },
) => ModelResponse | Promise<ModelResponse>;

export type MeteredProviderOptions = {
  provider: ModelProviderAdapter;
  runId: string;
  mode: string;
  policy: ResearchExecutionPolicy;
  pricing: PricingCatalog;
  ledger: CostLedger;
  pricingValidation?: LivePricingValidationOptions;
  replayStore?: ReplayCassetteStore;
  recordLiveCassettes?: boolean;
  mockResponder?: MockModelResponder;
  defaultMaxTokens?: number;
  local?: boolean;
  onReconciliation?: (reconciliation: CostReconciliation) => void;
  liveFailFastGate?: LiveModelCallFailFastGate;
};

export type MeteredProviderRuntime = {
  provider: ModelProviderAdapter;
  getReconciliations(): readonly CostReconciliation[];
  getLastReconciliation(): CostReconciliation | undefined;
};

export type LiveModelCallFailFastGate = {
  readonly signal: AbortSignal;
  isTripped(): boolean;
  trip(error: object): boolean;
  throwIfStopped(): void;
  track<T>(promise: Promise<T>): Promise<T>;
  drain(): Promise<void>;
};

export class UnknownModelUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnknownModelUsageError";
  }
}

const requestFingerprintByMeteredError = new WeakMap<object, string>();
const liveFailFastTriggerErrors = new WeakSet<object>();
const requestFingerprintResolverByMeteredProvider = new WeakMap<
  ModelProviderAdapter,
  (
    request: ModelRequest,
    config: ProviderConfig | undefined,
  ) => string | undefined
>();

export function meteredRequestFingerprintFromError(
  error: unknown,
): string | undefined {
  const key = weakMapKey(error);
  return key ? requestFingerprintByMeteredError.get(key) : undefined;
}

export function meteredRequestFingerprintForRequest(
  provider: ModelProviderAdapter,
  request: ModelRequest,
  config?: ProviderConfig,
): string | undefined {
  const resolve = requestFingerprintResolverByMeteredProvider.get(provider);
  if (!resolve) {
    return undefined;
  }
  try {
    return resolve(request, config);
  } catch {
    return undefined;
  }
}

export function isLiveModelCallFailFastTriggerError(
  error: unknown,
): boolean {
  const key = weakMapKey(error);
  return key ? liveFailFastTriggerErrors.has(key) : false;
}

export function createLiveModelCallFailFastGate(
  externalSignal?: AbortSignal,
): LiveModelCallFailFastGate {
  const controller = new AbortController();
  const signal =
    externalSignal && externalSignal !== controller.signal
      ? AbortSignal.any([controller.signal, externalSignal])
      : controller.signal;
  const pending = new Set<Promise<unknown>>();
  let tripped = false;

  return Object.freeze({
    signal,
    isTripped: () => tripped,
    trip(error) {
      if (tripped || externalSignal?.aborted) {
        return false;
      }
      tripped = true;
      liveFailFastTriggerErrors.add(error);
      controller.abort(liveModelCallFailFastAbortError());
      return true;
    },
    throwIfStopped() {
      if (!signal.aborted) {
        return;
      }
      throw abortReason(signal);
    },
    track<T>(promise: Promise<T>): Promise<T> {
      pending.add(promise);
      void promise.then(
        () => pending.delete(promise),
        () => pending.delete(promise),
      );
      void promise.catch(() => undefined);
      return promise;
    },
    async drain(): Promise<void> {
      while (pending.size > 0) {
        await Promise.allSettled([...pending]);
      }
    },
  });
}

export function createMeteredProvider(
  options: MeteredProviderOptions,
): ModelProviderAdapter {
  return createMeteredProviderRuntime(options).provider;
}

export function createMeteredProviderRuntime(
  options: MeteredProviderOptions,
): MeteredProviderRuntime {
  validateOptions(options);
  const policy = snapshotExecutionPolicy(options.policy);
  const immutableOptions: MeteredProviderOptions = Object.freeze({
    ...options,
    policy,
  });
  const { provider } = immutableOptions;
  const syntheticLocal = immutableOptions.local ?? false;
  const reconciliations: CostReconciliation[] = [];

  const captureReconciliation = (reconciliation: CostReconciliation): void => {
    const captured = Object.freeze({
      ...reconciliation,
      ...(reconciliation.overageReasons
        ? { overageReasons: Object.freeze([...reconciliation.overageReasons]) }
        : {}),
    });
    reconciliations.push(captured);
    immutableOptions.onReconciliation?.(captured);
  };

  const adapter: ModelProviderAdapter = {
    id: provider.id,
    ...(provider.capabilities
      ? {
          capabilities: {
            ...provider.capabilities,
            streaming: false,
          },
        }
      : {}),
    async listModels(config?: ProviderConfig) {
      if (policy.execution !== "live") {
        return policy.exactModelAllowlist.map((id) => ({
          id,
          label: id,
          local: syntheticLocal,
          supportsTools: provider.capabilities?.tools ?? false,
        }));
      }
      const listed = await provider.listModels(config);
      return listed.filter((model) => policy.exactModelAllowlist.includes(model.id));
    },
    async healthCheck(config?: ProviderConfig) {
      if (policy.execution !== "live") {
        return {
          ok: true,
          provider: provider.id,
          message: `${policy.execution} execution is isolated from provider credentials and network health.`,
          credential: "not-required",
          local: true,
        };
      }
      return provider.healthCheck(config);
    },
    async complete(
      request: ModelRequest,
      config?: ProviderConfig,
    ): Promise<ModelResponse> {
      try {
        const model = resolveExactModel(request, config, policy);
        if (policy.execution === "mock") {
          return runMock(immutableOptions, request, model);
        }
        if (policy.execution === "replay") {
          if (!immutableOptions.replayStore) {
            throw new Error("Replay execution requires a replay cassette store.");
          }
          const replayed =
            await immutableOptions.replayStore.replayWithReference({
              provider: provider.id,
              model,
              request,
            });
          const response = attachReplayReference(
            replayed.response,
            replayed.reference,
          );
          assertExactResponse(response, provider.id, model);
          return response;
        }
        const completion = runLive(
          immutableOptions,
          request,
          config,
          model,
          captureReconciliation,
        );
        return immutableOptions.liveFailFastGate
          ? await immutableOptions.liveFailFastGate.track(completion)
          : await completion;
      } catch (error) {
        if (
          policy.execution !== "live" ||
          !immutableOptions.liveFailFastGate ||
          immutableOptions.liveFailFastGate.isTripped() ||
          immutableOptions.liveFailFastGate.signal.aborted
        ) {
          throw error;
        }
        const bound = errorObject(error);
        immutableOptions.liveFailFastGate.trip(bound);
        throw bound;
      }
    },
    estimateCost(request: ModelRequest, config?: ProviderConfig): CostEstimate {
      const model = resolveExactModel(request, config, policy);
      if (policy.execution !== "live") {
        return {
          estimatedUsd: 0,
          promptTokens: 0,
          completionTokens: 0,
          local: true,
        };
      }
      const maxTokens = resolveMaxTokens(request, immutableOptions);
      const promptTokens = estimatePromptTokenUpperBound(request);
      const price = requireModelPrice(
        immutableOptions.pricing,
        provider.id,
        model,
      );
      return {
        estimatedUsd: nanoUsdToUsd(
          calculateWorstCaseCostNanoUsd(promptTokens, maxTokens, price),
        ),
        promptTokens,
        completionTokens: maxTokens,
        local: syntheticLocal,
      };
    },
  };

  requestFingerprintResolverByMeteredProvider.set(
    adapter,
    (request, config) => {
      if (policy.execution !== "live") {
        return undefined;
      }
      const model = resolveExactModel(request, config, policy);
      return liveRequestFingerprint(immutableOptions, request, model);
    },
  );

  return {
    provider: adapter,
    getReconciliations: () => Object.freeze([...reconciliations]),
    getLastReconciliation: () => reconciliations.at(-1),
  };
}

async function runMock(
  options: MeteredProviderOptions,
  request: ModelRequest,
  model: string,
): Promise<ModelResponse> {
  if (!options.mockResponder) {
    throw new Error("Mock execution requires an explicit mockResponder.");
  }
  const response = await options.mockResponder(request, {
    provider: options.provider.id,
    model,
  });
  assertExactResponse(response, options.provider.id, model);
  return response;
}

async function runLive(
  options: MeteredProviderOptions,
  request: ModelRequest,
  config: ProviderConfig | undefined,
  model: string,
  captureReconciliation: (reconciliation: CostReconciliation) => void,
): Promise<ModelResponse> {
  const failFastGate = options.liveFailFastGate;
  failFastGate?.throwIfStopped();
  validateExecutionPolicy(options.policy);
  validateModeBudget(options.mode, options.policy.modeBudgetUsd);
  validatePricingCatalogForLive(options.pricing, options.pricingValidation);
  const maxTokens = resolveMaxTokens(request, options);
  const promptTokenUpperBound = estimatePromptTokenUpperBound(request);
  const price = requireModelPrice(options.pricing, options.provider.id, model);
  const priceBoundedConfig = withPinnedOpenRouterPriceCeiling(
    config,
    options.provider.id,
    price,
  );
  const reservedNanoUsd = calculateWorstCaseCostNanoUsd(
    promptTokenUpperBound,
    maxTokens,
    price,
  );
  const requestFingerprint = liveRequestFingerprint(options, request, model);
  let localRequestAbortTrigger: object | undefined;
  const tripForLocalRequestAbort = (): void => {
    if (
      !request.signal ||
      !failFastGate ||
      failFastGate.signal.aborted
    ) {
      return;
    }
    const failure = bindMeteredRequestFingerprint(
      request.signal.reason ??
        Object.assign(
          new Error("Live model call request was aborted."),
          { name: "AbortError" },
        ),
      requestFingerprint,
    );
    if (failFastGate.trip(failure)) {
      localRequestAbortTrigger = failure;
    }
  };
  if (request.signal && failFastGate) {
    if (request.signal.aborted) {
      tripForLocalRequestAbort();
    } else {
      request.signal.addEventListener(
        "abort",
        tripForLocalRequestAbort,
        { once: true },
      );
    }
  }
  const reservation = await options.ledger.reserve({
    runId: options.runId,
    mode: options.mode,
    provider: options.provider.id,
    model,
    amountNanoUsd: reservedNanoUsd,
    globalLimitNanoUsd: usdToNanoUsd(options.policy.globalBudgetUsd),
    modeLimitNanoUsd: usdToNanoUsd(options.policy.modeBudgetUsd),
    requestFingerprint,
    pricingCatalogDigestSha256: options.pricing.catalogDigestSha256,
  }).catch((error: unknown) => {
    request.signal?.removeEventListener(
      "abort",
      tripForLocalRequestAbort,
    );
    throw error;
  });

  let providerDispatched = false;
  try {
    let providerResponseReceived = false;
    try {
      if (failFastGate?.signal.aborted) {
        throw (
          localRequestAbortTrigger ??
          abortReason(failFastGate.signal)
        );
      }
      const providerRequest: ModelRequest = {
        ...request,
        model,
        maxTokens,
        ...(options.policy.scored ? { requireExactModel: true } : {}),
        ...(failFastGate
          ? {
              signal: combineAbortSignals(
                failFastGate.signal,
                request.signal,
              ),
            }
          : {}),
      };
      providerDispatched = true;
      const response = await options.provider.complete(
        providerRequest,
        priceBoundedConfig,
      );
      providerResponseReceived = true;

      if (localRequestAbortTrigger) {
        throw localRequestAbortTrigger;
      }
      if (failFastGate?.isTripped()) {
        throw liveModelCallFailFastAbortError();
      }
      assertExactResponse(response, options.provider.id, model);
      const usage = requireSettlementUsage(response, options.policy.scored, price);
      let reconciliation: CostReconciliation;
      try {
        reconciliation = await options.ledger.settle(reservation.reservationId, {
          actualNanoUsd: usage.actualNanoUsd,
          promptTokens: usage.promptTokens,
          completionTokens: usage.completionTokens,
          costSource: usage.costSource,
        });
      } catch (error) {
        if (error instanceof CostKillSwitchError && error.reconciliation) {
          captureReconciliation(error.reconciliation);
        }
        throw error;
      }
      captureReconciliation(reconciliation);
      if (localRequestAbortTrigger) {
        throw localRequestAbortTrigger;
      }

      const meteredResponse: ModelResponse = {
        ...response,
        usage: {
          ...(response.usage ?? {
            provider: options.provider.id,
            model,
            local: options.local ?? false,
          }),
          provider: options.provider.id,
          model,
          promptTokens: usage.promptTokens,
          completionTokens: usage.completionTokens,
          totalTokens:
            response.usage?.totalTokens ??
            usage.promptTokens + usage.completionTokens,
          estimatedUsd: reconciliation.actualUsd,
        },
      };

      if (options.recordLiveCassettes) {
        if (!options.replayStore) {
          throw new Error("Live cassette recording requires a replay cassette store.");
        }
        const reference = await options.replayStore.record({
          provider: options.provider.id,
          model,
          request,
          response: meteredResponse,
        });
        if (localRequestAbortTrigger) {
          throw localRequestAbortTrigger;
        }
        return attachReplayReference(meteredResponse, reference);
      }
      if (localRequestAbortTrigger) {
        throw localRequestAbortTrigger;
      }
      return meteredResponse;
    } catch (error) {
      const failure = bindMeteredRequestFingerprint(
        localRequestAbortTrigger ?? error,
        requestFingerprint,
      );
      if (
        failFastGate &&
        !failFastGate.isTripped() &&
        !failFastGate.signal.aborted
      ) {
        failFastGate.trip(failure);
      }
      const snapshot = await options.ledger.snapshot();
      const state = snapshot.reservations.find(
        (candidate) => candidate.reservationId === reservation.reservationId,
      );
      if (state?.status === "reserved") {
        if (providerDispatched) {
          await options.ledger.markUnknown(
            reservation.reservationId,
            providerResponseReceived
              ? "Provider response could not be priced or verified; the reserved amount remains committed."
              : "Provider request failed after dispatch; whether the provider charged the request is unknown.",
          );
        } else {
          await options.ledger.markFailed(
            reservation.reservationId,
            "Live model call was stopped before provider dispatch.",
          );
        }
      }
      throw failure;
    }
  } catch (error) {
    throw bindMeteredRequestFingerprint(error, requestFingerprint);
  } finally {
    request.signal?.removeEventListener(
      "abort",
      tripForLocalRequestAbort,
    );
  }
}

function combineAbortSignals(
  required: AbortSignal,
  optional?: AbortSignal,
): AbortSignal {
  return optional && optional !== required
    ? AbortSignal.any([required, optional])
    : required;
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : liveModelCallFailFastAbortError();
}

function liveModelCallFailFastAbortError(): Error {
  const error = new Error(
    "Live model calls stopped after a provider call did not succeed.",
  );
  error.name = "AbortError";
  return error;
}

function errorObject(error: unknown): object {
  return (
    weakMapKey(error) ??
    new Error("Provider request failed with a non-Error rejection.")
  );
}

function withPinnedOpenRouterPriceCeiling(
  config: ProviderConfig | undefined,
  provider: string,
  price: {
    inputUsdPerMillionTokens: number;
    outputUsdPerMillionTokens: number;
  },
): ProviderConfig | undefined {
  if (provider !== "openrouter") {
    return config;
  }
  return {
    ...(config ?? {}),
    openRouter: {
      ...(config?.openRouter ?? {}),
      maxPrice: {
        prompt: canonicalNonNegativeDecimal(
          price.inputUsdPerMillionTokens,
        ),
        completion: canonicalNonNegativeDecimal(
          price.outputUsdPerMillionTokens,
        ),
        request: "0",
      },
    },
  };
}

function canonicalNonNegativeDecimal(value: number): string {
  const nanoUsd = usdToNanoUsd(value);
  const whole = Math.floor(nanoUsd / 1_000_000_000);
  const fractional = nanoUsd % 1_000_000_000;
  if (fractional === 0) {
    return String(whole);
  }
  return `${whole}.${String(fractional).padStart(9, "0").replace(/0+$/u, "")}`;
}

function liveRequestFingerprint(
  options: MeteredProviderOptions,
  request: ModelRequest,
  model: string,
): string {
  const replayRequest = {
    provider: options.provider.id,
    model,
    request,
  };
  return options.recordLiveCassettes && options.replayStore
    ? options.replayStore.fingerprint(replayRequest)
    : fingerprintReplayRequest(replayRequest);
}

function bindMeteredRequestFingerprint(
  error: unknown,
  requestFingerprint: string,
): object {
  const bound =
    weakMapKey(error) ??
    new Error("Provider request failed with a non-Error rejection.");
  requestFingerprintByMeteredError.set(bound, requestFingerprint);
  return bound;
}

function weakMapKey(value: unknown): object | undefined {
  return (
    (typeof value === "object" && value !== null) ||
    typeof value === "function"
  )
    ? value as object
    : undefined;
}

function requireSettlementUsage(
  response: ModelResponse,
  scored: boolean,
  price: {
    inputUsdPerMillionTokens: number;
    outputUsdPerMillionTokens: number;
  },
): {
  promptTokens: number;
  completionTokens: number;
  actualNanoUsd: number;
  costSource: "provider-authoritative" | "pinned-token-estimate";
} {
  const promptTokens = response.usage?.promptTokens;
  const completionTokens = response.usage?.completionTokens;
  if (
    !Number.isSafeInteger(promptTokens) ||
    (promptTokens ?? -1) < 0 ||
    !Number.isSafeInteger(completionTokens) ||
    (completionTokens ?? -1) < 0
  ) {
    throw new UnknownModelUsageError(
      scored
        ? "Scored live execution requires exact prompt and completion token usage."
        : "Live provider usage is missing the token counts required for cost settlement.",
    );
  }

  const authoritativeUsd = response.usage?.authoritativeUsd;
  if (authoritativeUsd !== undefined) {
    if (!Number.isFinite(authoritativeUsd) || authoritativeUsd < 0) {
      throw new UnknownModelUsageError(
        "Provider authoritative cost is not a non-negative finite USD amount.",
      );
    }
    return {
      promptTokens: promptTokens as number,
      completionTokens: completionTokens as number,
      actualNanoUsd: usdToNanoUsd(authoritativeUsd),
      costSource: "provider-authoritative",
    };
  }
  if (scored) {
    throw new UnknownModelUsageError(
      "Scored live execution requires authoritative provider cost; pinned pricing is reservation-only.",
    );
  }
  return {
    promptTokens: promptTokens as number,
    completionTokens: completionTokens as number,
    actualNanoUsd: calculateActualCostNanoUsd(
      promptTokens as number,
      completionTokens as number,
      price,
    ),
    costSource: "pinned-token-estimate",
  };
}

function resolveExactModel(
  request: ModelRequest,
  config: ProviderConfig | undefined,
  policy: ResearchExecutionPolicy,
): string {
  if (request.model && config?.model && request.model !== config.model) {
    throw new Error(
      `Conflicting exact model IDs were provided: ${request.model} and ${config.model}.`,
    );
  }
  return requireExactAllowedModel(request.model ?? config?.model, policy);
}

function resolveMaxTokens(
  request: ModelRequest,
  options: MeteredProviderOptions,
): number {
  const maxTokens = request.maxTokens ?? options.defaultMaxTokens;
  if (!Number.isSafeInteger(maxTokens) || (maxTokens ?? 0) <= 0) {
    throw new Error(
      options.policy.scored
        ? "Scored live requests require an explicit positive maxTokens ceiling."
        : "Live requests require a positive maxTokens ceiling.",
    );
  }
  return maxTokens as number;
}

function assertExactResponse(
  response: ModelResponse,
  provider: string,
  model: string,
): void {
  if (response.provider !== provider) {
    throw new Error(
      `Provider fallback or mismatch detected: requested ${provider}, received ${response.provider}.`,
    );
  }
  if (response.model !== model) {
    throw new Error(
      `Model fallback or mismatch detected: requested ${model}, received ${response.model}.`,
    );
  }
  if (response.usage?.provider && response.usage.provider !== provider) {
    throw new Error(
      "Provider usage metadata does not match the exact requested provider.",
    );
  }
  if (response.usage?.model && response.usage.model !== model) {
    throw new Error(
      "Provider usage metadata does not match the exact requested model.",
    );
  }
}

function validateOptions(options: MeteredProviderOptions): void {
  if (!options.runId.trim() || !options.mode.trim()) {
    throw new Error("Metered providers require non-empty run and mode IDs.");
  }
  validateExecutionPolicy(options.policy);
  validateModeBudget(options.mode, options.policy.modeBudgetUsd);
  if (options.policy.execution === "live") {
    validatePricingCatalogForLive(options.pricing, options.pricingValidation);
  }
  if (options.recordLiveCassettes && options.policy.execution !== "live") {
    throw new Error("Only live execution can record live replay cassettes.");
  }
  if (options.policy.execution === "mock" && !options.mockResponder) {
    throw new Error("Mock execution requires an explicit mockResponder.");
  }
}
