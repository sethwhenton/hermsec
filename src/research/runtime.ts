import path from "node:path";
import { CostLedger, type CostLedgerOptions } from "../agent/costTracker.js";
import {
  createMeteredProviderRuntime,
  type MeteredProviderRuntime,
  type MockModelResponder,
} from "../model/meteredProvider.js";
import type { ModelProviderAdapter } from "../model/provider.js";
import {
  snapshotExecutionPolicy,
  type ResearchExecutionPolicy,
} from "./execution.js";
import {
  createPricingCatalog,
  type LivePricingValidationOptions,
  type PricingCatalog,
  type PricingSnapshot,
} from "./pricing.js";
import {
  ReplayCassetteStore,
  type ReplayCassetteStoreOptions,
} from "./replay.js";

export type CreateResearchModelRuntimeInput = {
  ledgerOptions?: CostLedgerOptions;
} & CreateResearchModelRunInput;

export type CreateResearchModelRunInput = {
  runDirectory: string;
  runId: string;
  mode: string;
  policy: ResearchExecutionPolicy;
  provider: ModelProviderAdapter;
  pricingSnapshot: PricingSnapshot;
  pricingValidation?: LivePricingValidationOptions;
  replayDirectory?: string;
  replayOptions?: Omit<ReplayCassetteStoreOptions, "cursorId" | "scopeId">;
  replayScopeId?: string;
  recordLiveCassettes?: boolean;
  mockResponder?: MockModelResponder;
  defaultMaxTokens?: number;
  local?: boolean;
};

export type CreateResearchModelSuiteRuntimeInput = {
  suiteId: string;
  suiteDirectory: string;
  ledgerOptions?: CostLedgerOptions;
};

export type ResearchModelSuiteRuntime = {
  readonly suiteId: string;
  readonly suiteDirectory: string;
  readonly ledger: CostLedger;
  createRun(input: CreateResearchModelRunInput): ResearchModelRuntime;
};

export type ResearchModelRuntime = MeteredProviderRuntime & {
  runDirectory: string;
  ledger: CostLedger;
  pricing: PricingCatalog;
  replayStore?: ReplayCassetteStore;
  provenance: {
    pricingCatalogDigestSha256: string;
    pricingCapturedAt: string;
    pricingSource: string;
    execution: ResearchExecutionPolicy["execution"];
    runId: string;
    mode: string;
    costLedgerPath: string;
    suiteId?: string;
  };
};

const suiteLedgerPathById = new Map<string, string>();

export function createResearchModelSuiteRuntime(
  input: CreateResearchModelSuiteRuntimeInput,
): ResearchModelSuiteRuntime {
  assertNoArbitraryLedgerSelection(input, false);
  const suiteId = normalizeSuiteId(input.suiteId);
  const suiteDirectory = path.resolve(input.suiteDirectory);
  const ledgerPath = path.join(suiteDirectory, "cost-ledger.jsonl");
  bindSuiteLedgerPath(suiteId, ledgerPath);
  const ledger = freezeCostLedger(
    new CostLedger(ledgerPath, input.ledgerOptions),
  );

  return Object.freeze({
    suiteId,
    suiteDirectory,
    ledger,
    createRun(runInput: CreateResearchModelRunInput): ResearchModelRuntime {
      assertNoArbitraryLedgerSelection(runInput, true);
      const policy = snapshotExecutionPolicy(runInput.policy);
      const runDirectory = path.resolve(runInput.runDirectory);
      if (policy.execution === "live") {
        assertSharedLedgerOutsideRunDirectory(ledger.filePath, runDirectory);
      }
      return createBoundResearchModelRuntime(
        runInput,
        runDirectory,
        ledger,
        policy,
        suiteId,
      );
    },
  });
}

export function createResearchModelRuntime(
  input: CreateResearchModelRuntimeInput,
): ResearchModelRuntime {
  const policy = snapshotExecutionPolicy(input.policy);
  if (policy.execution === "live") {
    throw new Error(
      "Live research runs must be created through createResearchModelSuiteRuntime().",
    );
  }
  assertNoArbitraryLedgerSelection(input, false);
  const runDirectory = path.resolve(input.runDirectory);
  const ledger = freezeCostLedger(
    new CostLedger(
      path.join(runDirectory, "cost-ledger.jsonl"),
      input.ledgerOptions,
    ),
  );
  return createBoundResearchModelRuntime(input, runDirectory, ledger, policy);
}

function createBoundResearchModelRuntime(
  input: CreateResearchModelRunInput,
  runDirectory: string,
  ledger: CostLedger,
  policy: Readonly<ResearchExecutionPolicy>,
  suiteId?: string,
): ResearchModelRuntime {
  const pricing = createPricingCatalog(
    input.pricingSnapshot,
    policy.exactModelAllowlist,
  );
  const replayStore = input.replayDirectory
    ? new ReplayCassetteStore(input.replayDirectory, {
        ...input.replayOptions,
        cursorId: `${input.runId}\u0000${input.mode}`,
        ...(input.replayScopeId
          ? { scopeId: input.replayScopeId }
          : {}),
      })
    : undefined;
  if (policy.execution === "replay" && !replayStore) {
    throw new Error("Replay research runtime requires a replayDirectory.");
  }
  if (input.recordLiveCassettes && !replayStore) {
    throw new Error("Live cassette recording requires a replayDirectory.");
  }

  const metered = createMeteredProviderRuntime({
    provider: input.provider,
    runId: input.runId,
    mode: input.mode,
    policy,
    pricing,
    ledger,
    ...(input.pricingValidation
      ? { pricingValidation: input.pricingValidation }
      : {}),
    ...(replayStore ? { replayStore } : {}),
    ...(input.recordLiveCassettes !== undefined
      ? { recordLiveCassettes: input.recordLiveCassettes }
      : {}),
    ...(input.mockResponder ? { mockResponder: input.mockResponder } : {}),
    ...(input.defaultMaxTokens !== undefined
      ? { defaultMaxTokens: input.defaultMaxTokens }
      : {}),
    ...(input.local !== undefined ? { local: input.local } : {}),
  });

  return {
    ...metered,
    runDirectory,
    ledger,
    pricing,
    ...(replayStore ? { replayStore } : {}),
    provenance: Object.freeze({
      pricingCatalogDigestSha256: pricing.catalogDigestSha256,
      pricingCapturedAt: pricing.capturedAt,
      pricingSource: pricing.source,
      execution: policy.execution,
      runId: input.runId,
      mode: input.mode,
      costLedgerPath: ledger.filePath,
      ...(suiteId ? { suiteId } : {}),
    }),
  };
}

function normalizeSuiteId(value: string): string {
  const suiteId = value.trim();
  if (
    !suiteId ||
    suiteId.length > 200 ||
    /[\u0000-\u001f\u007f]/u.test(suiteId)
  ) {
    throw new Error(
      "Research suite ID must be a non-empty bounded string without control characters.",
    );
  }
  return suiteId;
}

function bindSuiteLedgerPath(suiteId: string, ledgerPath: string): void {
  const resolved = path.resolve(ledgerPath);
  const existing = suiteLedgerPathById.get(suiteId);
  if (existing && !samePath(existing, resolved)) {
    throw new Error(
      `Research suite ${suiteId} is already bound to a different global cost ledger.`,
    );
  }
  suiteLedgerPathById.set(suiteId, resolved);
}

function assertNoArbitraryLedgerSelection(
  input: object,
  rejectLedgerOptions: boolean,
): void {
  const forbidden = [
    "sharedLedger",
    "sharedLedgerPath",
    "ledger",
    "ledgerPath",
    "costLedgerPath",
    ...(rejectLedgerOptions ? ["ledgerOptions"] : []),
  ];
  for (const key of forbidden) {
    if (Object.prototype.hasOwnProperty.call(input, key)) {
      throw new Error(
        "Individual research runs cannot select or override the suite cost ledger.",
      );
    }
  }
}

function assertSharedLedgerOutsideRunDirectory(
  ledgerPath: string,
  runDirectory: string,
): void {
  const relative = path.relative(runDirectory, path.resolve(ledgerPath));
  if (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  ) {
    throw new Error(
      "Live research cost ledger must be shared outside the run artifact directory.",
    );
  }
}

function samePath(left: string, right: string): boolean {
  return process.platform === "win32"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function freezeCostLedger(ledger: CostLedger): CostLedger {
  Object.freeze(ledger);
  return ledger;
}
