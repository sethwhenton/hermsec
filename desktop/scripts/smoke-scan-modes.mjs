import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const electron = process.platform === "win32"
  ? resolve(root, "node_modules/.bin/electron.exe")
  : resolve(root, "node_modules/.bin/electron");
const electronFallback = process.platform === "win32"
  ? resolve(root, "node_modules/electron/dist/electron.exe")
  : electron;

const electronBinary = existsSync(electron) ? electron : electronFallback;
if (!existsSync(electronBinary)) {
  throw new Error(`Electron binary not found: ${electronBinary}`);
}

const env = {
  ...process.env,
  HERMSEC_HOME: process.env.HERMSEC_HOME ?? resolve(root, ".hermsec-v3", "scan-modes-smoke-home"),
  HERMSEC_SMOKE_SCAN_MODES_RUN: "true",
  HERMSEC_SMOKE_SCAN_MODES_OUT:
    process.env.HERMSEC_SMOKE_SCAN_MODES_OUT ?? resolve(root, "..", ".hermsec", "v3-scan-modes-smoke"),
};

const child = spawn(electronBinary, [
  ".",
  "--smoke-scan-modes",
  "--disable-gpu",
  "--disable-gpu-compositing",
  "--disable-software-rasterizer",
  "--no-sandbox",
], {
  cwd: root,
  env,
  stdio: "inherit",
  shell: false,
});

const timer = setTimeout(() => {
  child.kill("SIGKILL");
  console.error("Hermsec scan modes smoke test timed out.");
  process.exit(1);
}, 900_000);

child.on("exit", (code, signal) => {
  clearTimeout(timer);
  if (code !== null) {
    process.exit(code);
  }
  console.error(`Hermsec scan modes smoke test exited without a code${signal ? ` (${signal})` : ""}.`);
  process.exit(1);
});
