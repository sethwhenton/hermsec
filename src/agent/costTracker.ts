import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { redactForLog } from "./redaction.js";

export const NANO_USD_PER_USD = 1_000_000_000;
const TOKEN_PRICE_DENOMINATOR = 1_000_000n;

export type ModelUsage = {
  provider: string;
  model: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  estimatedUsd?: number;
  local: boolean;
};

export type TokenPrice = {
  inputUsdPerMillionTokens: number;
  outputUsdPerMillionTokens: number;
};

export type CostScope = {
  runId: string;
  mode: string;
  provider: string;
  model: string;
};

export type CostSource =
  | "provider-authoritative"
  | "pinned-token-estimate"
  | "reservation-conservative"
  | "known-not-charged";

export type CostOverageReason = "reservation" | "global" | "mode";

export type CostReservation = CostScope & {
  reservationId: string;
  reservedNanoUsd: number;
  reservedUsd: number;
  globalLimitNanoUsd: number;
  globalLimitUsd: number;
  modeLimitNanoUsd: number;
  modeLimitUsd: number;
  requestFingerprint?: string;
  pricingCatalogDigestSha256?: string;
};

export type CostLedgerAction =
  | "reserved"
  | "settled"
  | "failed"
  | "unknown"
  | "overage";

export type CostLedgerEntry = CostScope & {
  schemaVersion: 2;
  sequence: number;
  eventId: string;
  reservationId: string;
  action: CostLedgerAction;
  amountNanoUsd: number;
  amountUsd: number;
  timestamp: string;
  previousHash: string | null;
  hash: string;
  globalLimitNanoUsd?: number;
  modeLimitNanoUsd?: number;
  requestFingerprint?: string;
  pricingCatalogDigestSha256?: string;
  promptTokens?: number;
  completionTokens?: number;
  costSource?: CostSource;
  overageReasons?: readonly CostOverageReason[];
  reason?: string;
};

export type CostLedgerReservationState = CostReservation & {
  status: CostLedgerAction;
  committedNanoUsd: number;
  committedUsd: number;
  promptTokens?: number;
  completionTokens?: number;
  costSource?: CostSource;
  overageReasons?: readonly CostOverageReason[];
  reason?: string;
};

export type CostKillSwitchState = {
  tripped: boolean;
  reservationId?: string;
  eventId?: string;
  timestamp?: string;
  reason?: string;
  overageReasons?: readonly CostOverageReason[];
};

export type CostLedgerSnapshot = {
  entries: readonly CostLedgerEntry[];
  reservations: readonly CostLedgerReservationState[];
  committedNanoUsd: number;
  committedUsd: number;
  committedByRunModeNanoUsd: Readonly<Record<string, number>>;
  committedByRunMode: Readonly<Record<string, number>>;
  killSwitch: CostKillSwitchState;
};

type NanoOrUsdAmount =
  | { amountNanoUsd: number; amountUsd?: never }
  | { amountUsd: number; amountNanoUsd?: never };

type NanoOrUsdGlobalLimit =
  | { globalLimitNanoUsd: number; globalLimitUsd?: never }
  | { globalLimitUsd: number; globalLimitNanoUsd?: never };

type NanoOrUsdModeLimit =
  | { modeLimitNanoUsd: number; modeLimitUsd?: never }
  | { modeLimitUsd: number; modeLimitNanoUsd?: never };

export type ReserveCostInput = CostScope &
  NanoOrUsdAmount &
  NanoOrUsdGlobalLimit &
  NanoOrUsdModeLimit & {
    requestFingerprint?: string;
    pricingCatalogDigestSha256?: string;
  };

export type SettleCostInput = (
  | { actualNanoUsd: number; actualUsd?: never }
  | { actualUsd: number; actualNanoUsd?: never }
) & {
  promptTokens: number;
  completionTokens: number;
  costSource?: Extract<
    CostSource,
    "provider-authoritative" | "pinned-token-estimate"
  >;
};

export type CostReconciliation = CostLedgerReservationState & {
  actualNanoUsd: number;
  actualUsd: number;
  deltaNanoUsd: number;
  deltaUsd: number;
  terminal: "settled" | "overage";
};

export type CostLedgerOptions = {
  lockTimeoutMs?: number;
  staleLockMs?: number;
  retryDelayMs?: number;
};

export class BudgetExceededError extends Error {
  readonly currentNanoUsd: number;
  readonly requestedNanoUsd: number;
  readonly limitNanoUsd: number;
  readonly currentUsd: number;
  readonly requestedUsd: number;
  readonly limitUsd: number;
  readonly budget: "global" | "mode";

  constructor(input: {
    budget: "global" | "mode";
    currentNanoUsd: number;
    requestedNanoUsd: number;
    limitNanoUsd: number;
  }) {
    super(
      `${input.budget} cost budget would be exceeded: ` +
      `${formatNanoUsd(input.currentNanoUsd)} committed + ` +
      `${formatNanoUsd(input.requestedNanoUsd)} requested > ` +
      `${formatNanoUsd(input.limitNanoUsd)} limit.`,
    );
    this.name = "BudgetExceededError";
    this.currentNanoUsd = input.currentNanoUsd;
    this.requestedNanoUsd = input.requestedNanoUsd;
    this.limitNanoUsd = input.limitNanoUsd;
    this.currentUsd = nanoUsdToUsd(input.currentNanoUsd);
    this.requestedUsd = nanoUsdToUsd(input.requestedNanoUsd);
    this.limitUsd = nanoUsdToUsd(input.limitNanoUsd);
    this.budget = input.budget;
  }
}

export class CostKillSwitchError extends Error {
  readonly killSwitch: CostKillSwitchState;
  readonly reconciliation?: CostReconciliation;

  constructor(killSwitch: CostKillSwitchState, reconciliation?: CostReconciliation) {
    super(
      reconciliation
        ? `Actual provider cost tripped the research cost kill switch: ${formatNanoUsd(
            reconciliation.actualNanoUsd,
          )} charged; ${reconciliation.overageReasons?.join(", ") ?? "budget"} ceiling exceeded.`
        : `The research cost kill switch is already tripped${
            killSwitch.reason ? `: ${killSwitch.reason}` : "."
          }`,
    );
    this.name = "CostKillSwitchError";
    this.killSwitch = killSwitch;
    if (reconciliation) {
      this.reconciliation = reconciliation;
    }
  }
}

export class CostLedger {
  readonly filePath: string;
  readonly lockPath: string;
  private readonly lockTimeoutMs: number;
  private readonly staleLockMs: number;
  private readonly retryDelayMs: number;

  constructor(filePath: string, options: CostLedgerOptions = {}) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.lockTimeoutMs = options.lockTimeoutMs ?? 10_000;
    this.staleLockMs = options.staleLockMs ?? 120_000;
    this.retryDelayMs = options.retryDelayMs ?? 15;
  }

  async reserve(input: ReserveCostInput): Promise<CostReservation> {
    assertScope(input);
    const amountNanoUsd = resolveMoney(input, "reservation");
    const globalLimitNanoUsd = resolveGlobalLimit(input);
    const modeLimitNanoUsd = resolveModeLimit(input);
    assertDigest(input.pricingCatalogDigestSha256);

    return this.withLock(async () => {
      const entries = await this.readEntriesUnlocked();
      const snapshot = snapshotFromEntries(entries);
      if (snapshot.killSwitch.tripped) {
        throw new CostKillSwitchError(snapshot.killSwitch);
      }
      const key = runModeKey(input.runId, input.mode);
      const modeCommittedNanoUsd = snapshot.committedByRunModeNanoUsd[key] ?? 0;
      assertBudget(
        "global",
        snapshot.committedNanoUsd,
        amountNanoUsd,
        globalLimitNanoUsd,
      );
      assertBudget("mode", modeCommittedNanoUsd, amountNanoUsd, modeLimitNanoUsd);

      const reservation: CostReservation = {
        runId: input.runId,
        mode: input.mode,
        provider: input.provider,
        model: input.model,
        reservationId: randomUUID(),
        reservedNanoUsd: amountNanoUsd,
        reservedUsd: nanoUsdToUsd(amountNanoUsd),
        globalLimitNanoUsd,
        globalLimitUsd: nanoUsdToUsd(globalLimitNanoUsd),
        modeLimitNanoUsd,
        modeLimitUsd: nanoUsdToUsd(modeLimitNanoUsd),
        ...(input.requestFingerprint ? { requestFingerprint: input.requestFingerprint } : {}),
        ...(input.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: input.pricingCatalogDigestSha256 }
          : {}),
      };
      await this.appendUnlocked(entries, {
        ...scopeFromState(reservation),
        reservationId: reservation.reservationId,
        action: "reserved",
        amountNanoUsd,
        globalLimitNanoUsd,
        modeLimitNanoUsd,
        ...(reservation.requestFingerprint
          ? { requestFingerprint: reservation.requestFingerprint }
          : {}),
        ...(reservation.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: reservation.pricingCatalogDigestSha256 }
          : {}),
      });
      return reservation;
    });
  }

  async settle(
    reservationId: string,
    input: SettleCostInput,
  ): Promise<CostReconciliation> {
    const actualNanoUsd = resolveSettlementMoney(input);
    const costSource = input.costSource ?? "provider-authoritative";
    assertTokenCount(input.promptTokens, "prompt tokens");
    assertTokenCount(input.completionTokens, "completion tokens");

    return this.withLock(async () => {
      const entries = await this.readEntriesUnlocked();
      const snapshot = snapshotFromEntries(entries);
      const current = requireReservationState(snapshot, reservationId);
      if (current.status !== "reserved") {
        const reconciliation = requireIdempotentReconciliation(
          current,
          actualNanoUsd,
          costSource,
        );
        if (reconciliation.terminal === "overage") {
          throw new CostKillSwitchError(snapshot.killSwitch, reconciliation);
        }
        return reconciliation;
      }

      const runMode = runModeKey(current.runId, current.mode);
      const globalWithoutReservation =
        snapshot.committedNanoUsd - current.committedNanoUsd;
      const modeWithoutReservation =
        (snapshot.committedByRunModeNanoUsd[runMode] ?? 0) -
        current.committedNanoUsd;
      const overageReasons: CostOverageReason[] = [];
      if (actualNanoUsd > current.reservedNanoUsd) {
        overageReasons.push("reservation");
      }
      if (globalWithoutReservation + actualNanoUsd > current.globalLimitNanoUsd) {
        overageReasons.push("global");
      }
      if (modeWithoutReservation + actualNanoUsd > current.modeLimitNanoUsd) {
        overageReasons.push("mode");
      }

      const action = overageReasons.length > 0 ? "overage" : "settled";
      const reason =
        action === "overage"
          ? sanitizeReason(
              `Authoritative provider cost exceeded: ${overageReasons.join(", ")}.`,
            )
          : undefined;
      const appended = await this.appendUnlocked(entries, {
        ...scopeFromState(current),
        reservationId,
        action,
        amountNanoUsd: actualNanoUsd,
        ...(current.requestFingerprint
          ? { requestFingerprint: current.requestFingerprint }
          : {}),
        ...(current.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: current.pricingCatalogDigestSha256 }
          : {}),
        promptTokens: input.promptTokens,
        completionTokens: input.completionTokens,
        costSource,
        ...(overageReasons.length > 0 ? { overageReasons } : {}),
        ...(reason ? { reason } : {}),
      });
      const state = stateFromTerminalEntry(current, appended);
      const reconciliation = reconciliationFromState(state);
      if (action === "overage") {
        const killSwitch = killSwitchFromEntry(appended);
        throw new CostKillSwitchError(killSwitch, reconciliation);
      }
      return reconciliation;
    });
  }

  async markFailed(
    reservationId: string,
    reason: string,
  ): Promise<CostLedgerReservationState> {
    return this.transition(reservationId, {
      action: "failed",
      amountNanoUsd: 0,
      costSource: "known-not-charged",
      reason: sanitizeReason(reason),
    });
  }

  async markUnknown(
    reservationId: string,
    reason: string,
  ): Promise<CostLedgerReservationState> {
    return this.withLock(async () => {
      const entries = await this.readEntriesUnlocked();
      const current = requireReservationState(snapshotFromEntries(entries), reservationId);
      if (current.status !== "reserved") {
        return assertIdempotentTransition(current, "unknown");
      }
      const appended = await this.appendUnlocked(entries, {
        ...scopeFromState(current),
        reservationId,
        action: "unknown",
        amountNanoUsd: current.reservedNanoUsd,
        ...(current.requestFingerprint
          ? { requestFingerprint: current.requestFingerprint }
          : {}),
        ...(current.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: current.pricingCatalogDigestSha256 }
          : {}),
        costSource: "reservation-conservative",
        reason: sanitizeReason(reason),
      });
      return stateFromTerminalEntry(current, appended);
    });
  }

  async snapshot(): Promise<CostLedgerSnapshot> {
    return this.withLock(async () => snapshotFromEntries(await this.readEntriesUnlocked()));
  }

  private async transition(
    reservationId: string,
    terminal: {
      action: Extract<CostLedgerAction, "failed">;
      amountNanoUsd: number;
      costSource: CostSource;
      reason?: string;
    },
  ): Promise<CostLedgerReservationState> {
    return this.withLock(async () => {
      const entries = await this.readEntriesUnlocked();
      const current = requireReservationState(snapshotFromEntries(entries), reservationId);
      if (current.status !== "reserved") {
        return assertIdempotentTransition(
          current,
          terminal.action,
          terminal.amountNanoUsd,
        );
      }
      const appended = await this.appendUnlocked(entries, {
        ...scopeFromState(current),
        reservationId,
        action: terminal.action,
        amountNanoUsd: terminal.amountNanoUsd,
        ...(current.requestFingerprint
          ? { requestFingerprint: current.requestFingerprint }
          : {}),
        ...(current.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: current.pricingCatalogDigestSha256 }
          : {}),
        costSource: terminal.costSource,
        ...(terminal.reason ? { reason: terminal.reason } : {}),
      });
      return stateFromTerminalEntry(current, appended);
    });
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    const token = randomUUID();
    const startedAt = Date.now();

    while (true) {
      try {
        await fs.mkdir(this.lockPath);
        await fs.writeFile(
          path.join(this.lockPath, "owner.json"),
          JSON.stringify({ token, pid: process.pid, createdAt: new Date().toISOString() }),
          { encoding: "utf8", flag: "wx" },
        );
        break;
      } catch (error) {
        if (!isFileExistsError(error)) {
          throw error;
        }
        await this.reclaimStaleLock();
        if (Date.now() - startedAt >= this.lockTimeoutMs) {
          throw new Error(`Timed out waiting for cost ledger lock: ${this.lockPath}`);
        }
        await delay(this.retryDelayMs + Math.floor(Math.random() * this.retryDelayMs));
      }
    }

    try {
      return await operation();
    } finally {
      await this.releaseLock(token);
    }
  }

  private async reclaimStaleLock(): Promise<void> {
    let stat;
    try {
      stat = await fs.stat(this.lockPath);
    } catch (error) {
      if (isMissingFileError(error)) {
        return;
      }
      throw error;
    }
    if (Date.now() - stat.mtimeMs < this.staleLockMs) {
      return;
    }

    const owner = await readLockOwner(this.lockPath);
    if (owner && isProcessAlive(owner.pid)) {
      return;
    }

    const quarantine = `${this.lockPath}.stale-${randomUUID()}`;
    try {
      await fs.rename(this.lockPath, quarantine);
      await fs.rm(quarantine, { recursive: true, force: true });
    } catch (error) {
      if (!isMissingFileError(error)) {
        throw error;
      }
    }
  }

  private async releaseLock(token: string): Promise<void> {
    const owner = await readLockOwner(this.lockPath);
    if (!owner || owner.token !== token) {
      throw new Error("Cost ledger lock ownership changed before release.");
    }
    await fs.rm(this.lockPath, { recursive: true, force: true });
  }

  private async readEntriesUnlocked(): Promise<CostLedgerEntry[]> {
    let content: string;
    try {
      content = await fs.readFile(this.filePath, "utf8");
    } catch (error) {
      if (isMissingFileError(error)) {
        return [];
      }
      throw error;
    }
    if (!content) {
      return [];
    }
    if (!content.endsWith("\n")) {
      throw new Error("Cost ledger is truncated: the final event is incomplete.");
    }

    const entries: CostLedgerEntry[] = [];
    for (const [index, line] of content.trimEnd().split("\n").entries()) {
      let entry: CostLedgerEntry;
      try {
        entry = JSON.parse(line) as CostLedgerEntry;
      } catch {
        throw new Error(`Cost ledger event ${index + 1} is not valid JSON.`);
      }
      validateLedgerEntry(entry, entries[index - 1]);
      entries.push(entry);
    }
    return entries;
  }

  private async appendUnlocked(
    existing: readonly CostLedgerEntry[],
    input: CostScope & {
      reservationId: string;
      action: CostLedgerAction;
      amountNanoUsd: number;
      globalLimitNanoUsd?: number;
      modeLimitNanoUsd?: number;
      requestFingerprint?: string;
      pricingCatalogDigestSha256?: string;
      promptTokens?: number;
      completionTokens?: number;
      costSource?: CostSource;
      overageReasons?: readonly CostOverageReason[];
      reason?: string;
    },
  ): Promise<CostLedgerEntry> {
    assertNanoUsd(input.amountNanoUsd, "ledger event");
    const previous = existing.at(-1);
    const unsigned = {
      schemaVersion: 2 as const,
      sequence: existing.length + 1,
      eventId: randomUUID(),
      reservationId: input.reservationId,
      action: input.action,
      runId: input.runId,
      mode: input.mode,
      provider: input.provider,
      model: input.model,
      amountNanoUsd: input.amountNanoUsd,
      amountUsd: nanoUsdToUsd(input.amountNanoUsd),
      timestamp: new Date().toISOString(),
      previousHash: previous?.hash ?? null,
      ...(input.globalLimitNanoUsd !== undefined
        ? { globalLimitNanoUsd: input.globalLimitNanoUsd }
        : {}),
      ...(input.modeLimitNanoUsd !== undefined
        ? { modeLimitNanoUsd: input.modeLimitNanoUsd }
        : {}),
      ...(input.requestFingerprint
        ? { requestFingerprint: input.requestFingerprint }
        : {}),
      ...(input.pricingCatalogDigestSha256
        ? { pricingCatalogDigestSha256: input.pricingCatalogDigestSha256 }
        : {}),
      ...(input.promptTokens !== undefined ? { promptTokens: input.promptTokens } : {}),
      ...(input.completionTokens !== undefined
        ? { completionTokens: input.completionTokens }
        : {}),
      ...(input.costSource ? { costSource: input.costSource } : {}),
      ...(input.overageReasons ? { overageReasons: [...input.overageReasons] } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
    };
    const entry: CostLedgerEntry = {
      ...unsigned,
      hash: hashLedgerEvent(unsigned),
    };

    const handle = await fs.open(this.filePath, "a");
    try {
      await handle.writeFile(`${JSON.stringify(entry)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    return entry;
  }
}

export function summarizeModelUsage(usages: readonly ModelUsage[]): ModelUsage {
  const first = usages[0];
  const promptTokens = sumOptional(usages.map((usage) => usage.promptTokens));
  const completionTokens = sumOptional(usages.map((usage) => usage.completionTokens));
  const totalTokens = sumOptional(usages.map((usage) => usage.totalTokens));
  const estimatedNanoUsd = sumOptional(
    usages.map((usage) =>
      usage.estimatedUsd === undefined ? undefined : usdToNanoUsd(usage.estimatedUsd),
    ),
  );
  return {
    provider: first?.provider ?? "none",
    model: first?.model ?? "none",
    ...(promptTokens !== undefined ? { promptTokens } : {}),
    ...(completionTokens !== undefined ? { completionTokens } : {}),
    ...(totalTokens !== undefined ? { totalTokens } : {}),
    ...(estimatedNanoUsd !== undefined
      ? { estimatedUsd: nanoUsdToUsd(estimatedNanoUsd) }
      : {}),
    local: usages.every((usage) => usage.local),
  };
}

export function estimatePromptTokenUpperBound(requestPayload: unknown): number {
  const serialized = JSON.stringify(requestPayload);
  if (serialized === undefined) {
    throw new Error("Cannot estimate token usage for an unserializable request.");
  }
  // A token cannot encode less than one UTF-8 byte. The fixed allowance covers
  // provider-specific message framing and keeps reservations conservative.
  return Buffer.byteLength(serialized, "utf8") + 128;
}

export function calculateWorstCaseCostNanoUsd(
  promptTokenUpperBound: number,
  maxCompletionTokens: number,
  price: TokenPrice,
): number {
  return calculateTokenCostNanoUsd(
    promptTokenUpperBound,
    maxCompletionTokens,
    price,
  );
}

export function calculateWorstCaseCostUsd(
  promptTokenUpperBound: number,
  maxCompletionTokens: number,
  price: TokenPrice,
): number {
  return nanoUsdToUsd(
    calculateWorstCaseCostNanoUsd(promptTokenUpperBound, maxCompletionTokens, price),
  );
}

export function calculateActualCostNanoUsd(
  promptTokens: number,
  completionTokens: number,
  price: TokenPrice,
): number {
  return calculateTokenCostNanoUsd(promptTokens, completionTokens, price);
}

export function calculateActualCostUsd(
  promptTokens: number,
  completionTokens: number,
  price: TokenPrice,
): number {
  return nanoUsdToUsd(calculateActualCostNanoUsd(promptTokens, completionTokens, price));
}

export function usdToNanoUsd(value: number): number {
  assertUsd(value, "amount");
  const nanoUsd = Math.round(value * NANO_USD_PER_USD);
  assertNanoUsd(nanoUsd, "amount");
  return nanoUsd;
}

export function nanoUsdToUsd(value: number): number {
  assertNanoUsd(value, "amount");
  return value / NANO_USD_PER_USD;
}

function calculateTokenCostNanoUsd(
  promptTokens: number,
  completionTokens: number,
  price: TokenPrice,
): number {
  assertTokenCount(promptTokens, "prompt tokens");
  assertTokenCount(completionTokens, "completion tokens");
  assertTokenPrice(price);
  const inputRate = BigInt(usdToNanoUsd(price.inputUsdPerMillionTokens));
  const outputRate = BigInt(usdToNanoUsd(price.outputUsdPerMillionTokens));
  const numerator =
    BigInt(promptTokens) * inputRate + BigInt(completionTokens) * outputRate;
  const roundedUp =
    (numerator + TOKEN_PRICE_DENOMINATOR - 1n) / TOKEN_PRICE_DENOMINATOR;
  const nanoUsd = Number(roundedUp);
  assertNanoUsd(nanoUsd, "token calculation");
  return nanoUsd;
}

function snapshotFromEntries(entries: readonly CostLedgerEntry[]): CostLedgerSnapshot {
  const states = new Map<string, CostLedgerReservationState>();
  let killSwitch: CostKillSwitchState = { tripped: false };
  for (const entry of entries) {
    const current = states.get(entry.reservationId);
    if (entry.action === "reserved") {
      if (current) {
        throw new Error(`Cost ledger repeats reservation ${entry.reservationId}.`);
      }
      if (
        entry.globalLimitNanoUsd === undefined ||
        entry.modeLimitNanoUsd === undefined
      ) {
        throw new Error("Cost reservation is missing persisted budget ceilings.");
      }
      states.set(entry.reservationId, {
        ...scopeFromEntry(entry),
        reservationId: entry.reservationId,
        reservedNanoUsd: entry.amountNanoUsd,
        reservedUsd: nanoUsdToUsd(entry.amountNanoUsd),
        globalLimitNanoUsd: entry.globalLimitNanoUsd,
        globalLimitUsd: nanoUsdToUsd(entry.globalLimitNanoUsd),
        modeLimitNanoUsd: entry.modeLimitNanoUsd,
        modeLimitUsd: nanoUsdToUsd(entry.modeLimitNanoUsd),
        committedNanoUsd: entry.amountNanoUsd,
        committedUsd: nanoUsdToUsd(entry.amountNanoUsd),
        status: "reserved",
        ...(entry.requestFingerprint
          ? { requestFingerprint: entry.requestFingerprint }
          : {}),
        ...(entry.pricingCatalogDigestSha256
          ? { pricingCatalogDigestSha256: entry.pricingCatalogDigestSha256 }
          : {}),
      });
      continue;
    }
    if (!current || current.status !== "reserved") {
      throw new Error(
        `Cost ledger has an invalid ${entry.action} transition for ${entry.reservationId}.`,
      );
    }
    assertSameScope(current, entry);
    const terminal = stateFromTerminalEntry(current, entry);
    states.set(entry.reservationId, terminal);
    if (entry.action === "overage" && !killSwitch.tripped) {
      killSwitch = killSwitchFromEntry(entry);
    }
  }

  const committedByRunModeNanoUsd: Record<string, number> = {};
  let committedNanoUsd = 0;
  for (const state of states.values()) {
    committedNanoUsd = addSafeNanoUsd(committedNanoUsd, state.committedNanoUsd);
    const key = runModeKey(state.runId, state.mode);
    committedByRunModeNanoUsd[key] = addSafeNanoUsd(
      committedByRunModeNanoUsd[key] ?? 0,
      state.committedNanoUsd,
    );
  }
  const committedByRunMode = Object.fromEntries(
    Object.entries(committedByRunModeNanoUsd).map(([key, value]) => [
      key,
      nanoUsdToUsd(value),
    ]),
  );
  return {
    entries: [...entries],
    reservations: [...states.values()],
    committedNanoUsd,
    committedUsd: nanoUsdToUsd(committedNanoUsd),
    committedByRunModeNanoUsd: Object.freeze({ ...committedByRunModeNanoUsd }),
    committedByRunMode: Object.freeze(committedByRunMode),
    killSwitch,
  };
}

function requireReservationState(
  snapshot: CostLedgerSnapshot,
  reservationId: string,
): CostLedgerReservationState {
  if (!reservationId.trim()) {
    throw new Error("A reservation ID is required.");
  }
  const state = snapshot.reservations.find(
    (candidate) => candidate.reservationId === reservationId,
  );
  if (!state) {
    throw new Error(`Unknown cost reservation: ${reservationId}`);
  }
  return state;
}

function stateFromTerminalEntry(
  current: CostLedgerReservationState,
  entry: CostLedgerEntry,
): CostLedgerReservationState {
  return {
    ...scopeFromState(current),
    reservationId: current.reservationId,
    reservedNanoUsd: current.reservedNanoUsd,
    reservedUsd: current.reservedUsd,
    globalLimitNanoUsd: current.globalLimitNanoUsd,
    globalLimitUsd: current.globalLimitUsd,
    modeLimitNanoUsd: current.modeLimitNanoUsd,
    modeLimitUsd: current.modeLimitUsd,
    committedNanoUsd: entry.amountNanoUsd,
    committedUsd: nanoUsdToUsd(entry.amountNanoUsd),
    status: entry.action,
    ...(current.requestFingerprint
      ? { requestFingerprint: current.requestFingerprint }
      : {}),
    ...(current.pricingCatalogDigestSha256
      ? { pricingCatalogDigestSha256: current.pricingCatalogDigestSha256 }
      : {}),
    ...(entry.promptTokens !== undefined ? { promptTokens: entry.promptTokens } : {}),
    ...(entry.completionTokens !== undefined
      ? { completionTokens: entry.completionTokens }
      : {}),
    ...(entry.costSource ? { costSource: entry.costSource } : {}),
    ...(entry.overageReasons ? { overageReasons: [...entry.overageReasons] } : {}),
    ...(entry.reason ? { reason: entry.reason } : {}),
  };
}

function reconciliationFromState(
  state: CostLedgerReservationState,
): CostReconciliation {
  if (state.status !== "settled" && state.status !== "overage") {
    throw new Error(
      `Cost reservation ${state.reservationId} has no completed reconciliation.`,
    );
  }
  const deltaNanoUsd = state.committedNanoUsd - state.reservedNanoUsd;
  return {
    ...state,
    actualNanoUsd: state.committedNanoUsd,
    actualUsd: state.committedUsd,
    deltaNanoUsd,
    deltaUsd: nanoUsdToUsd(Math.abs(deltaNanoUsd)) * Math.sign(deltaNanoUsd),
    terminal: state.status,
  };
}

function requireIdempotentReconciliation(
  current: CostLedgerReservationState,
  actualNanoUsd: number,
  costSource: Exclude<SettleCostInput["costSource"], undefined>,
): CostReconciliation {
  if (
    (current.status !== "settled" && current.status !== "overage") ||
    current.committedNanoUsd !== actualNanoUsd ||
    current.costSource !== costSource
  ) {
    throw new Error(
      `Cost reservation ${current.reservationId} is already terminal as ${current.status}.`,
    );
  }
  return reconciliationFromState(current);
}

function assertIdempotentTransition(
  current: CostLedgerReservationState,
  action: Exclude<CostLedgerAction, "reserved" | "settled" | "overage">,
  amountNanoUsd?: number,
): CostLedgerReservationState {
  if (
    current.status !== action ||
    (amountNanoUsd !== undefined && current.committedNanoUsd !== amountNanoUsd)
  ) {
    throw new Error(
      `Cost reservation ${current.reservationId} is already terminal as ${current.status}.`,
    );
  }
  return current;
}

function validateLedgerEntry(
  entry: CostLedgerEntry,
  previous: CostLedgerEntry | undefined,
): void {
  if (entry.schemaVersion !== 2 || entry.sequence !== (previous?.sequence ?? 0) + 1) {
    throw new Error("Cost ledger sequence or schema version is invalid.");
  }
  if (entry.previousHash !== (previous?.hash ?? null)) {
    throw new Error(`Cost ledger hash chain is broken at event ${entry.sequence}.`);
  }
  assertScope(entry);
  assertNanoUsd(entry.amountNanoUsd, "ledger event");
  if (usdToNanoUsd(entry.amountUsd) !== entry.amountNanoUsd) {
    throw new Error(`Cost ledger USD display value is inconsistent at event ${entry.sequence}.`);
  }
  if (
    !["reserved", "settled", "failed", "unknown", "overage"].includes(
      entry.action,
    )
  ) {
    throw new Error(`Cost ledger action is invalid at event ${entry.sequence}.`);
  }
  if (entry.action === "reserved") {
    assertNanoUsd(entry.globalLimitNanoUsd, "global limit");
    assertNanoUsd(entry.modeLimitNanoUsd, "mode limit");
  } else if (entry.globalLimitNanoUsd !== undefined || entry.modeLimitNanoUsd !== undefined) {
    throw new Error("Only reservation events may persist budget ceilings.");
  }
  if (entry.action === "overage") {
    if (!entry.overageReasons?.length) {
      throw new Error("Cost overage events require at least one overage reason.");
    }
  } else if (entry.overageReasons !== undefined) {
    throw new Error("Only overage events may include overage reasons.");
  }
  assertDigest(entry.pricingCatalogDigestSha256);
  if (entry.promptTokens !== undefined) {
    assertTokenCount(entry.promptTokens, "prompt tokens");
  }
  if (entry.completionTokens !== undefined) {
    assertTokenCount(entry.completionTokens, "completion tokens");
  }
  const { hash, ...unsigned } = entry;
  if (hash !== hashLedgerEvent(unsigned)) {
    throw new Error(`Cost ledger integrity check failed at event ${entry.sequence}.`);
  }
}

function hashLedgerEvent(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child !== undefined) {
        output[key] = sortValue(child);
      }
    }
    return output;
  }
  return value;
}

function assertBudget(
  budget: "global" | "mode",
  currentNanoUsd: number,
  requestedNanoUsd: number,
  limitNanoUsd: number,
): void {
  if (currentNanoUsd + requestedNanoUsd > limitNanoUsd) {
    throw new BudgetExceededError({
      budget,
      currentNanoUsd,
      requestedNanoUsd,
      limitNanoUsd,
    });
  }
}

function assertScope(scope: CostScope): void {
  for (const [label, value] of [
    ["runId", scope.runId],
    ["mode", scope.mode],
    ["provider", scope.provider],
    ["model", scope.model],
  ] as const) {
    if (!value.trim()) {
      throw new Error(`Cost scope ${label} must be a non-empty string.`);
    }
  }
}

function resolveMoney(input: NanoOrUsdAmount, label: string): number {
  if ("amountNanoUsd" in input && input.amountNanoUsd !== undefined) {
    assertNanoUsd(input.amountNanoUsd, label);
    return input.amountNanoUsd;
  }
  if ("amountUsd" in input && input.amountUsd !== undefined) {
    return usdToNanoUsd(input.amountUsd);
  }
  throw new Error(`Cost ${label} requires exactly one amount.`);
}

function resolveSettlementMoney(input: SettleCostInput): number {
  if ("actualNanoUsd" in input && input.actualNanoUsd !== undefined) {
    assertNanoUsd(input.actualNanoUsd, "settled cost");
    return input.actualNanoUsd;
  }
  if ("actualUsd" in input && input.actualUsd !== undefined) {
    return usdToNanoUsd(input.actualUsd);
  }
  throw new Error("Settled cost requires exactly one actual amount.");
}

function resolveGlobalLimit(input: NanoOrUsdGlobalLimit): number {
  if ("globalLimitNanoUsd" in input && input.globalLimitNanoUsd !== undefined) {
    assertNanoUsd(input.globalLimitNanoUsd, "global limit");
    return input.globalLimitNanoUsd;
  }
  if ("globalLimitUsd" in input && input.globalLimitUsd !== undefined) {
    return usdToNanoUsd(input.globalLimitUsd);
  }
  throw new Error("Cost reservation requires a global limit.");
}

function resolveModeLimit(input: NanoOrUsdModeLimit): number {
  if ("modeLimitNanoUsd" in input && input.modeLimitNanoUsd !== undefined) {
    assertNanoUsd(input.modeLimitNanoUsd, "mode limit");
    return input.modeLimitNanoUsd;
  }
  if ("modeLimitUsd" in input && input.modeLimitUsd !== undefined) {
    return usdToNanoUsd(input.modeLimitUsd);
  }
  throw new Error("Cost reservation requires a mode limit.");
}

function assertUsd(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Cost ${label} must be a non-negative finite USD amount.`);
  }
}

function assertNanoUsd(value: number | undefined, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value ?? -1) < 0) {
    throw new Error(`Cost ${label} must be a non-negative safe nanodollar integer.`);
  }
}

function assertTokenCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Model ${label} must be a non-negative safe integer.`);
  }
}

function assertTokenPrice(price: TokenPrice): void {
  assertUsd(price.inputUsdPerMillionTokens, "input token price");
  assertUsd(price.outputUsdPerMillionTokens, "output token price");
}

function assertDigest(value: string | undefined): void {
  if (value !== undefined && !/^[a-f0-9]{64}$/u.test(value)) {
    throw new Error("Pricing catalog digest must be a lowercase SHA-256 value.");
  }
}

function assertSameScope(
  state: CostLedgerReservationState,
  entry: CostLedgerEntry,
): void {
  if (
    state.runId !== entry.runId ||
    state.mode !== entry.mode ||
    state.provider !== entry.provider ||
    state.model !== entry.model
  ) {
    throw new Error(`Cost ledger scope changed for reservation ${state.reservationId}.`);
  }
  if (
    entry.pricingCatalogDigestSha256 !== undefined &&
    state.pricingCatalogDigestSha256 !== entry.pricingCatalogDigestSha256
  ) {
    throw new Error(
      `Cost ledger pricing provenance changed for reservation ${state.reservationId}.`,
    );
  }
}

function scopeFromEntry(entry: CostLedgerEntry): CostScope {
  return {
    runId: entry.runId,
    mode: entry.mode,
    provider: entry.provider,
    model: entry.model,
  };
}

function scopeFromState(state: CostScope): CostScope {
  return {
    runId: state.runId,
    mode: state.mode,
    provider: state.provider,
    model: state.model,
  };
}

function runModeKey(runId: string, mode: string): string {
  return `${runId}\u0000${mode}`;
}

function addSafeNanoUsd(left: number, right: number): number {
  const result = left + right;
  assertNanoUsd(result, "ledger total");
  return result;
}

function formatNanoUsd(value: number): string {
  return `$${nanoUsdToUsd(value).toFixed(9)}`;
}

function sanitizeReason(reason: string): string {
  const redacted = redactForLog(reason).value;
  return String(redacted).replace(/\s+/g, " ").trim().slice(0, 300) || "unspecified";
}

function sumOptional(values: readonly (number | undefined)[]): number | undefined {
  const present = values.filter((value): value is number => value !== undefined);
  if (present.length === 0) {
    return undefined;
  }
  return present.reduce((total, value) => total + value, 0);
}

function killSwitchFromEntry(entry: CostLedgerEntry): CostKillSwitchState {
  return {
    tripped: true,
    reservationId: entry.reservationId,
    eventId: entry.eventId,
    timestamp: entry.timestamp,
    ...(entry.reason ? { reason: entry.reason } : {}),
    ...(entry.overageReasons
      ? { overageReasons: [...entry.overageReasons] }
      : {}),
  };
}

function isFileExistsError(error: unknown): boolean {
  return isNodeError(error) && error.code === "EEXIST";
}

function isMissingFileError(error: unknown): boolean {
  return isNodeError(error) && error.code === "ENOENT";
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

async function readLockOwner(
  lockPath: string,
): Promise<{ token: string; pid: number; createdAt: string } | undefined> {
  try {
    const parsed = JSON.parse(
      await fs.readFile(path.join(lockPath, "owner.json"), "utf8"),
    ) as { token?: unknown; pid?: unknown; createdAt?: unknown };
    if (
      typeof parsed.token === "string" &&
      typeof parsed.pid === "number" &&
      typeof parsed.createdAt === "string"
    ) {
      return { token: parsed.token, pid: parsed.pid, createdAt: parsed.createdAt };
    }
    return undefined;
  } catch (error) {
    if (isMissingFileError(error) || error instanceof SyntaxError) {
      return undefined;
    }
    throw error;
  }
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isNodeError(error) && error.code === "EPERM";
  }
}
