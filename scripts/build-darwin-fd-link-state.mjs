import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(import.meta.dirname, "..");
const outputDirectory = path.join(
  root,
  "dist",
  "src",
  "research",
  "native",
);
const output = path.join(
  outputDirectory,
  "hermsec-darwin-fd-link-state",
);

if (process.platform !== "darwin") {
  rmSync(output, { force: true });
  process.exit(0);
}

mkdirSync(outputDirectory, { recursive: true });
const source = fileURLToPath(
  new URL("./darwin-fd-link-state.c", import.meta.url),
);
const compiler = process.env.CC?.trim() || "cc";
const result = spawnSync(
  compiler,
  [
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-arch",
    "arm64",
    "-arch",
    "x86_64",
    "-mmacosx-version-min=12.0",
    "-Wl,-no_uuid",
    source,
    "-o",
    output,
  ],
  {
    cwd: root,
    encoding: "utf8",
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  },
);

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  throw new Error(
    `Failed to build the Darwin cleanup verifier: ${
      (result.stderr || result.stdout).trim()
    }`,
  );
}
chmodSync(output, 0o755);
