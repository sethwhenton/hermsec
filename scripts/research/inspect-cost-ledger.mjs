#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

const ledgerPath = process.argv[2];
if (!ledgerPath) {
  console.error("Usage: node scripts/research/inspect-cost-ledger.mjs <ledger.jsonl>");
  process.exitCode = 2;
} else {
  const modulePath = path.resolve("dist/src/agent/costTracker.js");
  const { CostLedger } = await import(pathToFileURL(modulePath).href);
  const snapshot = await new CostLedger(path.resolve(ledgerPath)).snapshot();
  console.log(JSON.stringify(snapshot, null, 2));
}
