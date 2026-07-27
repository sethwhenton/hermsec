import path from "node:path";
import type { FixtureManifestV2 } from "./schema.js";

export const FIXTURE_PROJECT_ROOT = "project" as const;

export type FixtureLayoutInventoryEntry = {
  path: string;
  kind: "directory" | "file";
};

export type ValidatedFixtureLayout = {
  projectRoot: typeof FIXTURE_PROJECT_ROOT;
  projectFiles: readonly {
    fixturePath: string;
    projectPath: string;
  }[];
  evaluatorFiles: readonly string[];
};

/**
 * Enforces a structural trust boundary: project bytes live below project/,
 * while every evaluator-only file is explicitly declared at fixture root.
 */
export function validateFixtureLayout(
  manifest: FixtureManifestV2,
  inventory: readonly FixtureLayoutInventoryEntry[],
): ValidatedFixtureLayout {
  if (manifest.projectRoot !== FIXTURE_PROJECT_ROOT) {
    throw new Error(
      `fixture ${manifest.id} projectRoot must be ${FIXTURE_PROJECT_ROOT}`,
    );
  }

  const entriesByPath = new Map<string, FixtureLayoutInventoryEntry>();
  const caseFoldedPaths = new Set<string>();
  for (const entry of inventory) {
    const canonical = canonicalInventoryPath(entry.path);
    if (canonical !== entry.path) {
      throw new Error(
        `fixture ${manifest.id} contains a non-canonical path alias: ${entry.path}`,
      );
    }
    const folded = canonical.toLowerCase();
    if (entriesByPath.has(canonical) || caseFoldedPaths.has(folded)) {
      throw new Error(
        `fixture ${manifest.id} contains a duplicate path alias: ${canonical}`,
      );
    }
    entriesByPath.set(canonical, entry);
    caseFoldedPaths.add(folded);
  }

  const root = entriesByPath.get(".");
  const projectRoot = entriesByPath.get(FIXTURE_PROJECT_ROOT);
  if (root?.kind !== "directory" || projectRoot?.kind !== "directory") {
    throw new Error(
      `fixture ${manifest.id} must contain a real ${FIXTURE_PROJECT_ROOT}/ directory`,
    );
  }

  const evaluatorFiles = ["fixture.json", ...manifest.evaluatorFiles];
  const evaluatorSet = new Set(evaluatorFiles);
  const projectPrefix = `${FIXTURE_PROJECT_ROOT}/`;
  const projectFiles: Array<{
    fixturePath: string;
    projectPath: string;
  }> = [];

  for (const entry of inventory) {
    if (entry.path === "." || entry.path === FIXTURE_PROJECT_ROOT) {
      continue;
    }
    if (entry.path.startsWith(projectPrefix)) {
      if (entry.kind === "file") {
        const projectPath = entry.path.slice(projectPrefix.length);
        assertCanonicalProjectPath(
          projectPath,
          `fixture ${manifest.id} project file`,
        );
        projectFiles.push({
          fixturePath: entry.path,
          projectPath,
        });
      }
      continue;
    }
    if (entry.kind === "directory") {
      throw new Error(
        `fixture ${manifest.id} contains an unclassified directory outside project/: ${entry.path}`,
      );
    }
    if (!evaluatorSet.has(entry.path)) {
      throw new Error(
        `fixture ${manifest.id} contains an unclassified file outside project/: ${entry.path}`,
      );
    }
  }

  for (const evaluatorFile of evaluatorFiles) {
    const entry = entriesByPath.get(evaluatorFile);
    if (entry?.kind !== "file") {
      throw new Error(
        `fixture ${manifest.id} evaluator file is missing or not regular: ${evaluatorFile}`,
      );
    }
  }
  if (projectFiles.length === 0) {
    throw new Error(`fixture ${manifest.id} project/ subtree is empty`);
  }

  const projectPaths = new Set(
    projectFiles.map((entry) => entry.projectPath),
  );
  for (const sourceFile of manifest.sourceFiles) {
    if (!projectPaths.has(sourceFile)) {
      throw new Error(
        `fixture ${manifest.id} source file is missing from project/: ${sourceFile}`,
      );
    }
  }
  for (const entrypoint of manifest.entrypoints) {
    if (!projectPaths.has(entrypoint)) {
      throw new Error(
        `fixture ${manifest.id} entrypoint is missing from project/: ${entrypoint}`,
      );
    }
  }

  return {
    projectRoot: FIXTURE_PROJECT_ROOT,
    projectFiles: projectFiles.sort((left, right) =>
      left.projectPath.localeCompare(right.projectPath),
    ),
    evaluatorFiles: [...evaluatorFiles].sort(),
  };
}

export function fixtureProjectPath(projectRelativePath: string): string {
  assertCanonicalProjectPath(projectRelativePath, "fixture project path");
  return `${FIXTURE_PROJECT_ROOT}/${projectRelativePath}`;
}

function canonicalInventoryPath(value: string): string {
  if (value === ".") {
    return value;
  }
  assertCanonicalProjectPath(value, "fixture inventory path");
  return value;
}

function assertCanonicalProjectPath(value: string, label: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    value.includes("\0") ||
    value.includes("\\") ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value) ||
    path.posix.normalize(value) !== value ||
    value === "." ||
    value === ".." ||
    value.startsWith("../") ||
    value.endsWith("/")
  ) {
    throw new Error(`${label} must be a canonical relative path`);
  }
}
