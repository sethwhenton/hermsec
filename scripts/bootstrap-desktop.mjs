import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const desktopRoot = resolve(root, "desktop");

const rootTsc = resolve(root, "node_modules", ".bin", process.platform === "win32" ? "tsc.cmd" : "tsc");
const desktopElectronVite = resolve(
  desktopRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "electron-vite.cmd" : "electron-vite",
);

if (!existsSync(rootTsc)) {
  console.log("Installing root Hermsec dependencies...");
  runNpm(["ci"], root);
}

if (!existsSync(desktopElectronVite)) {
  console.log("Installing Hermsec desktop dependencies...");
  runNpm(["ci"], desktopRoot);
}

console.log("Preparing Electron runtime...");
runNpm(["run", "setup:electron"], desktopRoot);

console.log("Preparing Hermsec CLI bundle for desktop...");
run(process.execPath, ["scripts/prepare-cli-bundle.mjs"], desktopRoot);

console.log("Hermsec desktop bootstrap complete.");

function runNpm(args, cwd) {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  runCommand(npmCommand, args, cwd);
}

function run(command, args, cwd) {
  runCommand(command, args, cwd);
}

function runCommand(command, args, cwd) {
  const isWindowsCmd = process.platform === "win32" && /\.cmd$/i.test(command);
  const executable = isWindowsCmd ? process.env.ComSpec ?? "cmd.exe" : command;
  const commandArgs = isWindowsCmd ? ["/d", "/s", "/c", command, ...args] : args;
  const result = spawnSync(executable, commandArgs, {
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
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}
