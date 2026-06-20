import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { app } from "electron";
import type { ProjectDirectory } from "../renderer/src/types/projects";

const PROJECT_STATE_FILE = "projects.json";

interface ProjectStateFile {
  projectPaths: string[];
  archivedPaths: string[];
  deletedPaths: string[];
}

export function listProjectDirectories(): ProjectDirectory[] {
  const state = readProjectState();
  const hidden = new Set([...state.archivedPaths, ...state.deletedPaths].map(normalizePath));

  return uniquePaths(state.projectPaths)
    .filter((projectPath) => existsSync(projectPath) && statSync(projectPath).isDirectory())
    .map(projectDirectoryFromPath)
    .filter((project) => !hidden.has(normalizePath(project.path)))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function registerProjectDirectory(projectPath: string): { ok: boolean; message: string } {
  const trimmed = projectPath.trim();
  if (!trimmed) {
    return { ok: false, message: "Choose a project folder before adding it to Hermsec." };
  }

  const normalizedPath = path.resolve(trimmed);
  if (!existsSync(normalizedPath) || !statSync(normalizedPath).isDirectory()) {
    return { ok: false, message: "Project folder was not found." };
  }

  const state = readProjectState();
  const normalized = normalizePath(normalizedPath);
  if (!state.projectPaths.map(normalizePath).includes(normalized)) {
    state.projectPaths.push(normalizedPath);
  }
  state.archivedPaths = state.archivedPaths.filter((item) => normalizePath(item) !== normalized);
  state.deletedPaths = state.deletedPaths.filter((item) => normalizePath(item) !== normalized);
  writeProjectState(state);
  return { ok: true, message: "Project added to Hermsec." };
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
  if (!existsSync(filePath)) return emptyProjectState();
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as Partial<ProjectStateFile>;
    return {
      projectPaths: Array.isArray(parsed.projectPaths) ? parsed.projectPaths.map(String) : [],
      archivedPaths: Array.isArray(parsed.archivedPaths) ? parsed.archivedPaths.map(String) : [],
      deletedPaths: Array.isArray(parsed.deletedPaths) ? parsed.deletedPaths.map(String) : [],
    };
  } catch {
    return emptyProjectState();
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

function emptyProjectState(): ProjectStateFile {
  return { projectPaths: [], archivedPaths: [], deletedPaths: [] };
}

function uniquePaths(paths: string[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const projectPath of paths) {
    const normalized = normalizePath(projectPath);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    unique.push(path.resolve(projectPath));
  }
  return unique;
}

function projectDirectoryFromPath(projectPath: string): ProjectDirectory {
  const resolved = path.resolve(projectPath);
  return {
    id: resolved,
    name: path.basename(resolved) || resolved,
    path: resolved,
    root: path.dirname(resolved),
  };
}
