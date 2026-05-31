import path from "node:path";

export function normalizeEvalPath(value: string, fixtureRoot?: string): string {
  const normalizedRoot = fixtureRoot ? normalizePathText(fixtureRoot) : undefined;
  let normalized = normalizePathText(value);

  if (normalizedRoot) {
    const rootWithSlash = normalizedRoot.endsWith("/") ? normalizedRoot : `${normalizedRoot}/`;
    const lowerPath = normalized.toLowerCase();
    const lowerRoot = normalizedRoot.toLowerCase();
    const lowerRootWithSlash = rootWithSlash.toLowerCase();

    if (lowerPath === lowerRoot) {
      normalized = "";
    } else if (lowerPath.startsWith(lowerRootWithSlash)) {
      normalized = normalized.slice(rootWithSlash.length);
    }
  }

  normalized = path.posix.normalize(normalized);
  if (normalized === ".") {
    return "";
  }

  return normalized.replace(/^\.\//, "");
}

export function normalizePathText(value: string): string {
  return value.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");
}

export function pathMatches(expectedPath: string | undefined, actualPath: string | undefined): boolean {
  if (!expectedPath || !actualPath) {
    return false;
  }

  return normalizeEvalPath(expectedPath).toLowerCase() === normalizeEvalPath(actualPath).toLowerCase();
}
