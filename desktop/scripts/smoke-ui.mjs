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

const preferredElectron = process.env.HERMSEC_ELECTRON_BINARY;
const electronBinary = preferredElectron && existsSync(preferredElectron)
  ? preferredElectron
  : existsSync(electron)
    ? electron
    : electronFallback;
if (!existsSync(electronBinary)) {
  throw new Error(`Electron binary not found: ${electronBinary}`);
}

const env = {
  ...process.env,
  HERMSEC_HOME: process.env.HERMSEC_HOME ?? resolve(root, ".hermsec-v3", "ui-smoke-home"),
  HERMSEC_SMOKE_UI: "true",
};

const child = spawn(electronBinary, [
  ".",
  "--smoke-ui",
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
  console.error("Hermsec UI smoke test timed out.");
  process.exit(1);
}, 120_000);

child.on("exit", (code) => {
  clearTimeout(timer);
  process.exit(code ?? 0);
});
