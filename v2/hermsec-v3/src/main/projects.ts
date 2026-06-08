import { existsSync, mkdirSync, readFileSync, renameSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { app } from "electron";
import type { ProjectDirectory } from "../renderer/src/types/projects";
import { findHermsecRoot } from "./scan";

const TEST_PROJECTS_DIR = "Test projects";
const PROJECT_STATE_FILE = "projects.json";

interface ProjectStateFile {
  archivedPaths: string[];
  deletedPaths: string[];
}

export function testProjectsRoot(): string {
  return path.join(findHermsecRoot(), TEST_PROJECTS_DIR);
}

export function listProjectDirectories(): ProjectDirectory[] {
  const root = testProjectsRoot();
  if (!existsSync(root)) return [];
  const state = readProjectState();
  const hidden = new Set([...state.archivedPaths, ...state.deletedPaths].map(normalizePath));

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
    .filter((project) => !hidden.has(normalizePath(project.path)))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function archiveProjectDirectory(projectPath: string): { ok: boolean; message: string } {
  const state = readProjectState();
  const normalized = normalizePath(projectPath);
  if (!state.archivedPaths.map(normalizePath).includes(normalized)) {
    state.archivedPaths.push(projectPath);
  }
  state.deletedPaths = state.deletedPaths.filter((item) => normalizePath(item) !== normalized);
  writeProjectState(state);
  return { ok: true, message: "Project archived in Hermsec." };
}

export function deleteProjectDirectory(projectPath: string): { ok: boolean; message: string } {
  const state = readProjectState();
  const normalized = normalizePath(projectPath);
  if (!state.deletedPaths.map(normalizePath).includes(normalized)) {
    state.deletedPaths.push(projectPath);
  }
  state.archivedPaths = state.archivedPaths.filter((item) => normalizePath(item) !== normalized);
  writeProjectState(state);
  return { ok: true, message: "Project removed from Hermsec. The folder was not deleted from disk." };
}

function projectStatePath(): string {
  const dir = app.getPath("userData");
  mkdirSync(dir, { recursive: true });
  return path.join(dir, PROJECT_STATE_FILE);
}

function readProjectState(): ProjectStateFile {
  const filePath = projectStatePath();
  if (!existsSync(filePath)) return { archivedPaths: [], deletedPaths: [] };
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as Partial<ProjectStateFile>;
    return {
      archivedPaths: Array.isArray(parsed.archivedPaths) ? parsed.archivedPaths.map(String) : [],
      deletedPaths: Array.isArray(parsed.deletedPaths) ? parsed.deletedPaths.map(String) : [],
    };
  } catch {
    return { archivedPaths: [], deletedPaths: [] };
  }
}

function writeProjectState(state: ProjectStateFile): void {
  const filePath = projectStatePath();
  const tmp = `${filePath}.tmp`;
  writeFileSync(tmp, JSON.stringify(state, null, 2), "utf8");
  renameSync(tmp, filePath);
}

function normalizePath(filePath: string): string {
  return path.resolve(filePath).toLowerCase();
}
