import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  join,
  resolve,
} from "node:path";

const desktopRoot = resolve(import.meta.dirname, "..");
const electronShim = process.platform === "win32"
  ? resolve(desktopRoot, "node_modules/.bin/electron.exe")
  : resolve(desktopRoot, "node_modules/.bin/electron");
const electronFallback = process.platform === "win32"
  ? resolve(desktopRoot, "node_modules/electron/dist/electron.exe")
  : electronShim;
const preferredElectron = process.env.HERMSEC_ELECTRON_BINARY;
const electronBinary = preferredElectron && existsSync(preferredElectron)
  ? preferredElectron
  : existsSync(electronShim)
    ? electronShim
    : electronFallback;

if (!existsSync(electronBinary)) {
  throw new Error(`Electron binary not found: ${electronBinary}`);
}

const temporaryRoot = resolve(tmpdir());
const smokeHome = mkdtempSync(join(temporaryRoot, "hermsec-conversation-smoke-"));
const env = {
  ...process.env,
  HERMSEC_HOME: smokeHome,
  HERMSEC_SMOKE_CONVERSATION: "true",
  HERMSEC_DISABLE_GPU: "true",
};

const child = spawn(electronBinary, [
  ".",
  "--smoke-conversation",
  "--disable-gpu",
  "--disable-gpu-compositing",
  "--disable-software-rasterizer",
  "--no-sandbox",
], {
  cwd: desktopRoot,
  env,
  stdio: "inherit",
  shell: false,
});

let timedOut = false;
let finished = false;
const timer = setTimeout(() => {
  timedOut = true;
  child.kill("SIGKILL");
  console.error("Hermsec conversation smoke test timed out.");
}, 120_000);

child.on("error", (error) => {
  console.error(`Could not launch the Hermsec conversation smoke test: ${error.message}`);
  finish(1);
});

child.on("exit", (code) => {
  finish(timedOut ? 1 : (code ?? 1));
});

function finish(exitCode) {
  if (finished) return;
  finished = true;
  clearTimeout(timer);
  removeIsolatedHome();
  process.exitCode = exitCode;
}

function removeIsolatedHome() {
  const target = resolve(smokeHome);
  if (
    dirname(target) !== temporaryRoot ||
    !basename(target).startsWith("hermsec-conversation-smoke-")
  ) {
    throw new Error(`Refusing to remove unexpected smoke directory: ${target}`);
  }
  rmSync(target, { recursive: true, force: true });
}
