import { spawn, spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

if (process.platform === "win32") {
  spawnSync("taskkill", ["/F", "/IM", "electron.exe"], { stdio: "ignore", shell: true });
}

rmSync(resolve(root, "out"), { recursive: true, force: true });

const child = spawn(process.platform === "win32" ? "bun.cmd" : "bun", ["run", "dev"], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
});

child.on("exit", (code) => process.exit(code ?? 0));
