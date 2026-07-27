import { canonicalJson, sha256 } from "./integrity.js";

export const OPENROUTER_MODELS_CATALOG_URL = "https://openrouter.ai/api/v1/models";
export const DEFAULT_LIVE_PRICING_MAX_AGE_MS = 48 * 60 * 60 * 1_000;

export type ModelPrice = {
  provider: string;
  model: string;
  inputUsdPerMillionTokens: number;
  outputUsdPerMillionTokens: number;
  contextLength: number;
  supportedParameters: readonly string[];
};

export type PricingSnapshotUnsigned = {
  schemaVersion: 2;
  capturedAt: string;
  source: string;
  prices: readonly ModelPrice[];
};

export type PricingSnapshot = PricingSnapshotUnsigned & {
  catalogDigestSha256: string;
};

export type PricingCatalog = {
  schemaVersion: 2;
  capturedAt: string;
  source: string;
  catalogDigestSha256: string;
  entries: ReadonlyMap<string, Readonly<ModelPrice>>;
};

export type LivePricingValidationOptions = {
  now?: Date;
  maxAgeMs?: number;
  expectedSource?: string;
};

export function sealPricingSnapshot(
  snapshot: PricingSnapshotUnsigned,
): PricingSnapshot {
  const normalized = normalizeSnapshot(snapshot);
  return {
    ...normalized,
    catalogDigestSha256: calculatePricingCatalogDigest(normalized),
  };
}

export function calculatePricingCatalogDigest(
  snapshot: PricingSnapshotUnsigned,
): string {
  const normalized = normalizeSnapshot(snapshot);
  return sha256(canonicalJson({
    models: normalized.prices.map((price) => ({
      id: price.model,
      provider: price.provider,
      pricing: {
        promptUsdPerMillionTokens: price.inputUsdPerMillionTokens,
        completionUsdPerMillionTokens: price.outputUsdPerMillionTokens,
      },
      contextLength: price.contextLength,
      supportedParameters: price.supportedParameters,
    })),
  }));
}

export function createPricingCatalog(
  snapshot: PricingSnapshot,
  exactModelAllowlist: readonly string[],
): PricingCatalog {
  const normalized = normalizeSnapshot(snapshot);
  if (!/^[a-f0-9]{64}$/u.test(snapshot.catalogDigestSha256)) {
    throw new Error("Pricing snapshots require a lowercase SHA-256 catalog digest.");
  }
  const expectedDigest = calculatePricingCatalogDigest(normalized);
  if (snapshot.catalogDigestSha256 !== expectedDigest) {
    throw new Error(
      "Pricing snapshot catalog digest does not match its prices or provenance.",
    );
  }

  const allowlist = new Set(exactModelAllowlist);
  if (allowlist.size !== exactModelAllowlist.length || allowlist.size === 0) {
    throw new Error(
      "The exact model allowlist must be non-empty and contain no duplicates.",
    );
  }

  const entries = new Map<string, Readonly<ModelPrice>>();
  for (const price of normalized.prices) {
    if (!allowlist.has(price.model)) {
      throw new Error(
        `Pricing includes a model outside the exact allowlist: ${price.model}`,
      );
    }
    const key = pricingKey(price.provider, price.model);
    if (entries.has(key)) {
      throw new Error(
        `Duplicate pricing entry for ${price.provider}/${price.model}.`,
      );
    }
    entries.set(key, Object.freeze({ ...price }));
  }

  for (const model of allowlist) {
    if (![...entries.values()].some((entry) => entry.model === model)) {
      throw new Error(
        `The pricing snapshot is missing the allowlisted model: ${model}`,
      );
    }
  }
  return Object.freeze({
    schemaVersion: 2 as const,
    capturedAt: normalized.capturedAt,
    source: normalized.source,
    catalogDigestSha256: snapshot.catalogDigestSha256,
    entries,
  });
}

export function validatePricingCatalogForLive(
  catalog: PricingCatalog,
  options: LivePricingValidationOptions = {},
): void {
  const now = options.now ?? new Date();
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_LIVE_PRICING_MAX_AGE_MS;
  const expectedSource =
    options.expectedSource ?? OPENROUTER_MODELS_CATALOG_URL;
  if (!Number.isFinite(now.getTime())) {
    throw new Error("Live pricing validation requires a valid current time.");
  }
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs <= 0) {
    throw new Error("Live pricing freshness must be a positive millisecond integer.");
  }
  if (catalog.source !== expectedSource) {
    throw new Error(
      `Live pricing provenance mismatch: expected ${expectedSource}, received ${catalog.source}.`,
    );
  }
  const currentDigest = calculatePricingCatalogDigest({
    schemaVersion: 2,
    capturedAt: catalog.capturedAt,
    source: catalog.source,
    prices: [...catalog.entries.values()],
  });
  if (currentDigest !== catalog.catalogDigestSha256) {
    throw new Error(
      "Live pricing catalog was mutated after provenance validation.",
    );
  }
  const capturedAtMs = Date.parse(catalog.capturedAt);
  const ageMs = now.getTime() - capturedAtMs;
  if (ageMs < -5 * 60 * 1_000) {
    throw new Error("Live pricing snapshot timestamp is implausibly in the future.");
  }
  if (ageMs > maxAgeMs) {
    throw new Error(
      `Live pricing snapshot is stale by ${ageMs} ms; maximum age is ${maxAgeMs} ms.`,
    );
  }
}

export function requireModelPrice(
  catalog: PricingCatalog,
  provider: string,
  model: string,
): Readonly<ModelPrice> {
  const price = catalog.entries.get(pricingKey(provider, model));
  if (!price) {
    throw new Error(
      `No pinned price is configured for exact model ${provider}/${model}.`,
    );
  }
  return price;
}

export function pricingKey(provider: string, model: string): string {
  return `${provider.trim()}\u0000${model.trim()}`;
}

function normalizeSnapshot(
  snapshot: PricingSnapshotUnsigned,
): PricingSnapshotUnsigned {
  if (snapshot.schemaVersion !== 2) {
    throw new Error("Pricing snapshot schema version is unsupported.");
  }
  assertIsoTimestamp(snapshot.capturedAt);
  if (!snapshot.source.trim()) {
    throw new Error("Pricing snapshots require a non-empty source URL.");
  }
  const prices = snapshot.prices.map((price) => {
    assertModelPrice(price);
    return {
      ...price,
      supportedParameters: [...price.supportedParameters].sort(),
    };
  });
  prices.sort((left, right) =>
    `${left.provider}\u0000${left.model}`.localeCompare(
      `${right.provider}\u0000${right.model}`,
    ),
  );
  return {
    schemaVersion: 2,
    capturedAt: new Date(snapshot.capturedAt).toISOString(),
    source: snapshot.source.trim(),
    prices,
  };
}

function assertModelPrice(price: ModelPrice): void {
  if (
    !/^[a-z0-9-]+$/u.test(price.provider) ||
    !/^[A-Za-z0-9._:/-]+$/u.test(price.model)
  ) {
    throw new Error("Pricing entries require exact provider and model identifiers.");
  }
  assertNonNegativeFinite(price.inputUsdPerMillionTokens, "input token price");
  assertNonNegativeFinite(price.outputUsdPerMillionTokens, "output token price");
  if (!Number.isSafeInteger(price.contextLength) || price.contextLength <= 0) {
    throw new Error("Model context length must be a positive safe integer.");
  }
  if (
    !Array.isArray(price.supportedParameters) ||
    price.supportedParameters.length === 0 ||
    price.supportedParameters.some(
      (parameter) =>
        typeof parameter !== "string" ||
        !/^[a-z0-9_]+$/u.test(parameter),
    ) ||
    new Set(price.supportedParameters).size !== price.supportedParameters.length
  ) {
    throw new Error(
      "Model supported parameters must be a non-empty unique string list.",
    );
  }
}

function assertNonNegativeFinite(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Model ${label} must be a non-negative finite number.`);
  }
}

function assertIsoTimestamp(value: string): void {
  if (!value || Number.isNaN(Date.parse(value))) {
    throw new Error("Pricing snapshots require a valid capturedAt timestamp.");
  }
}
