import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PREBUILT_SHA256 =
  "37ea88028a8df0c73d0123a652bd2923b6bf214ce380f08194062ac83bb4c40d";
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
const prebuilt = path.join(
  root,
  "scripts",
  "prebuilt",
  "hermsec-darwin-fd-link-state",
);

if (process.platform !== "darwin") {
  const prebuiltBytes = readFileSync(prebuilt);
  const digest = createHash("sha256")
    .update(prebuiltBytes)
    .digest("hex");
  if (digest !== PREBUILT_SHA256) {
    throw new Error(
      "The prebuilt universal Darwin cleanup verifier failed integrity verification.",
    );
  }
  mkdirSync(outputDirectory, { recursive: true });
  copyFileSync(prebuilt, output);
  chmodSync(output, 0o755);
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
