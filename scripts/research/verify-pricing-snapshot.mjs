#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const snapshotPath = path.resolve(
  process.argv[2] ?? "scripts/research/openrouter-pricing.snapshot.json",
);
const modulePath = path.resolve("dist/src/research/pricing.js");
const {
  calculatePricingCatalogDigest,
  createPricingCatalog,
} = await import(pathToFileURL(modulePath).href);

const snapshot = JSON.parse(await fs.readFile(snapshotPath, "utf8"));
const digest = calculatePricingCatalogDigest(snapshot);
const allowlist = snapshot.prices.map((entry) => entry.model);
createPricingCatalog(snapshot, allowlist);

if (digest !== snapshot.catalogDigestSha256) {
  console.error(
    JSON.stringify({
      valid: false,
      expected: snapshot.catalogDigestSha256,
      actual: digest,
      snapshotPath,
    }, null, 2),
  );
  process.exitCode = 1;
} else {
  console.log(JSON.stringify({
    valid: true,
    digest,
    models: allowlist,
    capturedAt: snapshot.capturedAt,
    source: snapshot.source,
    networkRequests: 0,
  }, null, 2));
}
