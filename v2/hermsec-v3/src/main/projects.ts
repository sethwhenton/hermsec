import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import type { ProjectDirectory } from "../renderer/src/types/projects";
import { findHermsecRoot } from "./scan";

const TEST_PROJECTS_DIR = "Test projects";

export function testProjectsRoot(): string {
  return path.join(findHermsecRoot(), TEST_PROJECTS_DIR);
}

export function listProjectDirectories(): ProjectDirectory[] {
  const root = testProjectsRoot();
  if (!existsSync(root)) return [];

  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const projectPath = path.join(root, entry.name);
      return {
        id: projectPath,
        name: entry.name,
        path: projectPath,
        root,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}
