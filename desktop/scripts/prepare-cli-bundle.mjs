import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");
const appRoot = resolve(import.meta.dirname, "..");
const bundleRoot = resolve(appRoot, "resources/hermsec-cli");
const rootTsc = resolve(root, "node_modules", "typescript", "bin", "tsc");

if (!existsSync(rootTsc)) {
  throw new Error(
    [
      "Root Hermsec dependencies are missing; packaging never installs them automatically.",
      "Run the reviewed setup explicitly before packaging:",
      "  PMG_DISABLE_TELEMETRY=true pmg npm ci --ignore-scripts",
      "Then rerun the desktop packaging command.",
    ].join("\n"),
  );
}

// Do not route packaging through a root package script. The bundle needs one
// known local compiler invocation after dependencies have been explicitly
// installed by the caller; invoking npm here would reopen the package-script
// surface and make the packaging path harder to audit.
rmSync(resolve(root, "dist"), { recursive: true, force: true });
runNode([rootTsc, "-p", resolve(root, "tsconfig.json")], root);
runNode([resolve(root, "scripts/build-darwin-fd-link-state.mjs")], root);

const distSrc = resolve(root, "dist/src");
if (!existsSync(resolve(distSrc, "bin/hermsec.js"))) {
  throw new Error(`Hermsec CLI build was not found at ${distSrc}`);
}

rmSync(bundleRoot, { recursive: true, force: true });
mkdirSync(resolve(bundleRoot, "dist"), { recursive: true });
cpSync(distSrc, resolve(bundleRoot, "dist/src"), { recursive: true });

const rootPackage = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
writeFileSync(
  resolve(bundleRoot, "package.json"),
  JSON.stringify(
    {
      name: "hermsec-cli-bundle",
      version: rootPackage.version ?? "0.1.0",
      private: true,
      type: "module",
      bin: {
        hermsec: "./dist/src/bin/hermsec.js",
      },
    },
    null,
    2,
  ),
  "utf8",
);

if (existsSync(resolve(root, ".npmrc"))) {
  cpSync(resolve(root, ".npmrc"), resolve(bundleRoot, ".npmrc"));
}

console.log(`Hermsec CLI bundle prepared at ${bundleRoot}`);

function runNode(args, cwd) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    stdio: "inherit",
    shell: false,
    env: {
      ...process.env,
      PMG_DISABLE_TELEMETRY: process.env.PMG_DISABLE_TELEMETRY ?? "true",
    },
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${process.execPath} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}
