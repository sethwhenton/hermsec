import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../../..");
const appRoot = resolve(import.meta.dirname, "..");
const bundleRoot = resolve(appRoot, "resources/hermsec-cli");

run(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build:core"], root);

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

function run(command, args, cwd) {
  const commandArgs = process.platform === "win32"
    ? ["/d", "/s", "/c", command, ...args]
    : args;
  const executable = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : command;
  const result = spawnSync(executable, commandArgs, {
    cwd,
    stdio: "inherit",
    shell: false,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}
