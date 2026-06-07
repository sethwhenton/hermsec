import { cpSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const source = resolve(root, "src/main/reportTemplates");
const target = resolve(root, "out/main/reportTemplates");

if (!existsSync(source)) {
  throw new Error(`Report template source not found: ${source}`);
}

mkdirSync(target, { recursive: true });
cpSync(source, target, { recursive: true });
