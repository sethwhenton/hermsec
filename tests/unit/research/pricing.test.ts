import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  requireExactAllowedModel,
  validateModeBudget,
  validateExecutionPolicy,
} from "../../../src/research/execution.js";
import {
  calculatePricingCatalogDigest,
  createPricingCatalog,
  OPENROUTER_MODELS_CATALOG_URL,
  requireModelPrice,
  sealPricingSnapshot,
  validatePricingCatalogForLive,
  type PricingSnapshot,
  type PricingSnapshotUnsigned,
} from "../../../src/research/pricing.js";

const MODEL = "deepseek/deepseek-v4-flash";

test("pricing catalog digest binds the canonical exact model subset", () => {
  const snapshot = sealPricingSnapshot(unsignedSnapshot());
  const catalog = createPricingCatalog(snapshot, [MODEL]);

  assert.equal(
    requireModelPrice(catalog, "openrouter", MODEL)
      .outputUsdPerMillionTokens,
    0.1876,
  );
  assert.equal(catalog.catalogDigestSha256, calculatePricingCatalogDigest(snapshot));
  assert.throws(
    () =>
      createPricingCatalog(
        {
          ...snapshot,
          prices: snapshot.prices.map((price) => ({
            ...price,
            contextLength: price.contextLength + 1,
          })),
        },
        [MODEL],
      ),
    /catalog digest does not match/i,
  );
  assert.throws(
    () => createPricingCatalog(snapshot, [MODEL, "xiaomi/mimo-v2.5"]),
    /missing the allowlisted model/i,
  );
  assert.throws(
    () => requireModelPrice(catalog, "openrouter", "xiaomi/mimo-v2.5"),
    /no pinned price/i,
  );
});

test("live pricing rejects stale, future, or wrong-provenance catalogs", () => {
  const snapshot = sealPricingSnapshot(unsignedSnapshot());
  const catalog = createPricingCatalog(snapshot, [MODEL]);

  assert.doesNotThrow(() =>
    validatePricingCatalogForLive(catalog, {
      now: new Date("2026-07-25T12:00:00.000Z"),
      maxAgeMs: 24 * 60 * 60 * 1_000,
    }),
  );
  assert.throws(
    () =>
      validatePricingCatalogForLive(catalog, {
        now: new Date("2026-07-27T12:00:00.000Z"),
        maxAgeMs: 24 * 60 * 60 * 1_000,
      }),
    /stale/i,
  );
  assert.throws(
    () =>
      validatePricingCatalogForLive(catalog, {
        now: new Date("2026-07-24T00:00:00.000Z"),
      }),
    /future/i,
  );

  const wrongSource = sealPricingSnapshot({
    ...unsignedSnapshot(),
    source: "https://example.invalid/catalog",
  });
  assert.throws(
    () =>
      validatePricingCatalogForLive(createPricingCatalog(wrongSource, [MODEL]), {
        now: new Date("2026-07-25T12:00:00.000Z"),
      }),
    /provenance mismatch/i,
  );

  const mutableEntries = catalog.entries as Map<
    string,
    ReturnType<typeof requireModelPrice>
  >;
  mutableEntries.set(
    `openrouter\u0000${MODEL}`,
    Object.freeze({
      ...requireModelPrice(catalog, "openrouter", MODEL),
      contextLength: 1,
    }),
  );
  assert.throws(
    () =>
      validatePricingCatalogForLive(catalog, {
        now: new Date("2026-07-25T12:00:00.000Z"),
      }),
    /mutated/i,
  );
});

test("committed pricing snapshot has exact reviewed values and no placeholder", async () => {
  const snapshotPath = path.resolve(
    "scripts/research/openrouter-pricing.snapshot.json",
  );
  const raw = await fs.readFile(snapshotPath, "utf8");
  const snapshot = JSON.parse(raw) as PricingSnapshot;
  const catalog = createPricingCatalog(
    snapshot,
    snapshot.prices.map((price) => price.model),
  );

  assert.match(snapshot.catalogDigestSha256, /^[a-f0-9]{64}$/);
  assert.equal(
    catalog.catalogDigestSha256,
    "6f8d00241ac08042056be6181027d1b6b40ce0a9eee0467912de2f370ad3b49d",
  );
  assert.deepEqual(
    snapshot.prices.map((price) => [
      price.model,
      price.inputUsdPerMillionTokens,
      price.outputUsdPerMillionTokens,
      price.contextLength,
      price.supportedParameters.includes("tools"),
    ]),
    [
      ["deepseek/deepseek-v4-flash", 0.14, 0.28, 1048576, true],
      ["xiaomi/mimo-v2.5", 0.14, 0.28, 1050000, true],
      ["minimax/minimax-m3", 0.3, 1.2, 1048576, true],
    ],
  );
});

test("execution policy requires explicit live spend and exact integer ceilings", () => {
  const base = {
    scored: true,
    noModelFallback: true as const,
    exactModelAllowlist: [MODEL],
    globalBudgetUsd: 3.25,
    modeBudgetUsd: 0.015,
  };
  assert.throws(
    () =>
      validateExecutionPolicy({
        ...base,
        execution: "live",
        allowSpend: false,
      }),
    /explicit allowSpend/i,
  );
  assert.throws(
    () =>
      validateExecutionPolicy({
        ...base,
        execution: "replay",
        allowSpend: true,
      }),
    /must not enable spending/i,
  );
  assert.equal(
    requireExactAllowedModel(MODEL, {
      ...base,
      execution: "live",
      allowSpend: true,
    }),
    MODEL,
  );
  assert.throws(
    () =>
      requireExactAllowedModel("unapproved/model", {
        ...base,
        execution: "live",
        allowSpend: true,
      }),
    /outside the exact research allowlist/i,
  );
  assert.throws(
    () =>
      validateExecutionPolicy({
        ...base,
        execution: "live",
        allowSpend: true,
        globalBudgetUsd: 3.250000001,
      }),
    /cannot exceed USD 3\.25/i,
  );
  assert.equal(validateModeBudget("moa-high", 0.12), "moa-high");
  assert.throws(
    () => validateModeBudget("single-agent", 0.015000001),
    /cannot exceed USD 0\.015/i,
  );
});

function unsignedSnapshot(): PricingSnapshotUnsigned {
  return {
    schemaVersion: 2,
    capturedAt: "2026-07-25T00:00:00.000Z",
    source: OPENROUTER_MODELS_CATALOG_URL,
    prices: [
      {
        provider: "openrouter",
        model: MODEL,
        inputUsdPerMillionTokens: 0.0938,
        outputUsdPerMillionTokens: 0.1876,
        contextLength: 1048576,
        supportedParameters: [
          "tools",
          "max_tokens",
          "tool_choice",
          "response_format",
        ],
      },
    ],
  };
}
