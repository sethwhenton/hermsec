import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createBundledResourceIntegrityAnchor } from "../src/main/bundledRuntimeIntegrity.ts";

const appRoot = path.resolve(import.meta.dirname, "..");
const resourcesRoot = path.join(appRoot, "resources");
const generatedPath = path.join(appRoot, "src", "main", "generated", "bundledIntegrity.ts");

export function writeBundledIntegrityAnchor(input = {}) {
  const root = path.resolve(input.resourcesRoot ?? resourcesRoot);
  if (!existsSync(path.join(root, "hermsec-cli"))) {
    throw new Error("Hermsec CLI bundle is missing; run prepare:cli-bundle before creating the integrity anchor.");
  }
  const anchor = createBundledResourceIntegrityAnchor({
    resourcesRoot: root,
    platform: input.platform ?? process.platform,
    arch: input.arch ?? process.arch,
  });
  const output = path.resolve(input.outputPath ?? generatedPath);
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(
    output,
    [
      "// Generated during packaging. It is bundled into Electron main code, not shipped beside mutable resources.",
      `export const BUNDLED_RESOURCE_INTEGRITY = ${JSON.stringify(anchor, null, 2)} as const;`,
      "",
    ].join("\n"),
    "utf8",
  );
  return { output, anchor };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = writeBundledIntegrityAnchor();
  console.log(`Hermsec bundled integrity anchor prepared at ${result.output}`);
}
