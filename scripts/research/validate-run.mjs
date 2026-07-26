#!/usr/bin/env node

import path from "node:path";
import { pathToFileURL } from "node:url";

const runDirectory = process.argv[2];
if (!runDirectory) {
  console.error("Usage: node scripts/research/validate-run.mjs <run-directory>");
  process.exitCode = 2;
} else {
  const modulePath = path.resolve("dist/src/research/runManifest.js");
  const { validateRunArtifacts } = await import(pathToFileURL(modulePath).href);
  const result = await validateRunArtifacts(path.resolve(runDirectory));
  console.log(JSON.stringify(result, null, 2));
  if (!result.valid) {
    process.exitCode = 1;
  }
}
