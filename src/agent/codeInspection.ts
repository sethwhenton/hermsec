import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORES, readTextFile, walkSourceTree, type SourceFile } from "../core/files.js";
import { toPosixPath } from "../shared/paths.js";
import { clampText, redactSecrets } from "../shared/text.js";

export type CodeInspectionFile = {
  path: string;
  size: number;
  language: SourceFile["language"];
  kind: SourceFile["kind"];
};

export type CodeSearchResult = {
  file: string;
  line: number;
  column: number;
  preview: string;
};

export type FileSnippet = {
  file: string;
  startLine: number;
  endLine: number;
  text: string;
  truncated: boolean;
};

export type CodeInspectionSnapshot = {
  files: CodeInspectionFile[];
  searches: Array<{
    query: string;
    matches: CodeSearchResult[];
    truncated: boolean;
  }>;
  snippets: FileSnippet[];
  limits: {
    files: number;
    searchResults: number;
    snippets: number;
  };
  truncated: boolean;
};

export type ListFilesHelper = (input?: {
  limit?: number;
  pathIncludes?: string;
  kind?: SourceFile["kind"];
  language?: SourceFile["language"];
}) => CodeInspectionFile[];

export type SearchCodeHelper = (input: {
  query: string;
  limit?: number;
  maxMatchesPerFile?: number;
  caseSensitive?: boolean;
  pathPrefix?: string;
}) => Promise<{ matches: CodeSearchResult[]; truncated: boolean }>;

export type ReadFileSnippetHelper = (input: {
  path: string;
  startLine?: number;
  endLine?: number;
  contextLines?: number;
  maxChars?: number;
}) => Promise<FileSnippet>;

export type CodeInspectionRuntime = {
  repoRoot: string;
  listFiles: ListFilesHelper;
  list_files: ListFilesHelper;
  searchCode: SearchCodeHelper;
  search_code: SearchCodeHelper;
  readFileSnippet: ReadFileSnippetHelper;
  read_file_snippet: ReadFileSnippetHelper;
  buildSnapshot(input?: {
    maxFiles?: number;
    maxSearches?: number;
    maxSearchResults?: number;
    maxSnippets?: number;
    searchQueries?: string[];
  }): Promise<CodeInspectionSnapshot>;
};

export type CodeInspectionRuntimeOptions = {
  maxFiles?: number;
  maxTextFileBytes?: number;
  maxLockfileBytes?: number;
  maxSearchFiles?: number;
};

const DEFAULT_MAX_FILES = 5_000;
const DEFAULT_MAX_TEXT_FILE_BYTES = 750_000;
const DEFAULT_MAX_LOCKFILE_BYTES = 2_000_000;
const DEFAULT_MAX_SEARCH_FILES = 1_200;
const DEFAULT_LIST_LIMIT = 200;
const DEFAULT_SEARCH_LIMIT = 80;
const DEFAULT_MATCHES_PER_FILE = 5;
const DEFAULT_SNIPPET_CHARS = 6_000;
const DEFAULT_SNIPPET_LINES = 80;
const MAX_QUERY_LENGTH = 200;
const MAX_CONTEXT_LINES = 20;
const MAX_SNIPPET_LINES = 160;

const SECURITY_SEARCH_QUERIES = [
  "eval(",
  "innerHTML",
  "dangerouslySetInnerHTML",
  "child_process",
  "exec(",
  "spawn(",
  "shell=True",
  "subprocess.",
  "pickle.loads",
  "yaml.load",
  "jwt.verify",
  "password",
  "api_key",
  "secret",
  "token",
  "SELECT ",
  "rawQuery",
  "redirect(",
  "cors(",
] as const;

export async function createCodeInspectionRuntime(
  repoRoot: string,
  options: CodeInspectionRuntimeOptions = {},
): Promise<CodeInspectionRuntime> {
  const root = await normalizeRepoRoot(repoRoot);
  const walk = await walkSourceTree(root, {
    maxFiles: boundedInt(options.maxFiles, DEFAULT_MAX_FILES, 1, 25_000),
    maxTextFileBytes: boundedInt(options.maxTextFileBytes, DEFAULT_MAX_TEXT_FILE_BYTES, 1_000, 5_000_000),
    maxLockfileBytes: boundedInt(options.maxLockfileBytes, DEFAULT_MAX_LOCKFILE_BYTES, 1_000, 10_000_000),
  });
  const files = walk.files;
  const fileByPath = new Map(files.map((file) => [file.relativePath, file]));
  const maxSearchFiles = boundedInt(options.maxSearchFiles, DEFAULT_MAX_SEARCH_FILES, 1, DEFAULT_MAX_FILES);

  function listFiles(input: Parameters<CodeInspectionRuntime["listFiles"]>[0] = {}): CodeInspectionFile[] {
    const limit = boundedInt(input.limit, DEFAULT_LIST_LIMIT, 1, DEFAULT_MAX_FILES);
    const includes = input.pathIncludes?.trim().toLowerCase();
    return files
      .filter((file) => !input.kind || file.kind === input.kind)
      .filter((file) => !input.language || file.language === input.language)
      .filter((file) => !includes || file.relativePath.toLowerCase().includes(includes))
      .slice(0, limit)
      .map(toInspectionFile);
  }

  async function searchCode(input: Parameters<CodeInspectionRuntime["searchCode"]>[0]): ReturnType<CodeInspectionRuntime["searchCode"]> {
    const query = normalizeQuery(input.query);
    const limit = boundedInt(input.limit, DEFAULT_SEARCH_LIMIT, 1, 500);
    const maxMatchesPerFile = boundedInt(input.maxMatchesPerFile, DEFAULT_MATCHES_PER_FILE, 1, 25);
    const pathPrefix = input.pathPrefix ? assertSafeRelativePath(input.pathPrefix, root) : undefined;
    const needle = input.caseSensitive ? query : query.toLowerCase();
    const matches: CodeSearchResult[] = [];
    let searchedFiles = 0;

    for (const file of files) {
      if (pathPrefix && !file.relativePath.startsWith(pathPrefix)) {
        continue;
      }
      if (searchedFiles >= maxSearchFiles) {
        return { matches, truncated: true };
      }
      searchedFiles += 1;

      let content: string;
      try {
        content = await readTextFile(file);
      } catch {
        continue;
      }
      const lines = content.split(/\r?\n/);
      let fileMatches = 0;
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        const haystack = input.caseSensitive ? line : line.toLowerCase();
        const column = haystack.indexOf(needle);
        if (column === -1) {
          continue;
        }
        matches.push({
          file: file.relativePath,
          line: index + 1,
          column: column + 1,
          preview: clampText(redactSecrets(line), 240),
        });
        fileMatches += 1;
        if (matches.length >= limit) {
          return { matches, truncated: true };
        }
        if (fileMatches >= maxMatchesPerFile) {
          break;
        }
      }
    }
    return { matches, truncated: false };
  }

  async function readFileSnippet(input: Parameters<CodeInspectionRuntime["readFileSnippet"]>[0]): ReturnType<CodeInspectionRuntime["readFileSnippet"]> {
    const relativePath = assertSafeRelativePath(input.path, root);
    const file = fileByPath.get(relativePath);
    if (!file) {
      throw new Error(`File is not in the allowed source set: ${relativePath}`);
    }
    const realFilePath = await fs.realpath(file.absolutePath);
    assertWithinRoot(realFilePath, root);

    const content = await readTextFile(file);
    const lines = content.split(/\r?\n/);
    const requestedStart = boundedInt(input.startLine, 1, 1, Math.max(lines.length, 1));
    const requestedEnd = boundedInt(input.endLine, Math.min(lines.length, requestedStart + DEFAULT_SNIPPET_LINES - 1), requestedStart, lines.length);
    const contextLines = boundedInt(input.contextLines, 0, 0, MAX_CONTEXT_LINES);
    const startLine = Math.max(1, requestedStart - contextLines);
    const endLine = Math.min(lines.length, Math.min(requestedEnd + contextLines, startLine + MAX_SNIPPET_LINES - 1));
    const maxChars = boundedInt(input.maxChars, DEFAULT_SNIPPET_CHARS, 200, 20_000);

    const selectedLines: string[] = [];
    let truncated = false;
    for (let lineNumber = startLine; lineNumber <= endLine; lineNumber += 1) {
      const rawLine = lines[lineNumber - 1] ?? "";
      selectedLines.push(`${lineNumber}: ${redactSecrets(rawLine)}`);
      if (selectedLines.join("\n").length > maxChars) {
        truncated = true;
        break;
      }
    }
    const text = selectedLines.join("\n");
    return {
      file: file.relativePath,
      startLine,
      endLine: Math.min(endLine, startLine + selectedLines.length - 1),
      text: text.length > maxChars ? `${text.slice(0, maxChars - 3)}...` : text,
      truncated,
    };
  }

  async function buildSnapshot(input: Parameters<CodeInspectionRuntime["buildSnapshot"]>[0] = {}): ReturnType<CodeInspectionRuntime["buildSnapshot"]> {
    const maxFiles = boundedInt(input.maxFiles, 160, 1, 500);
    const maxSearches = boundedInt(input.maxSearches, 12, 1, 25);
    const maxSearchResults = boundedInt(input.maxSearchResults, 40, 1, 200);
    const maxSnippets = boundedInt(input.maxSnippets, 14, 0, 60);
    const searchQueries = (input.searchQueries ?? SECURITY_SEARCH_QUERIES).slice(0, maxSearches);
    const searches: CodeInspectionSnapshot["searches"] = [];
    const snippets: FileSnippet[] = [];
    const snippetKeys = new Set<string>();

    for (const query of searchQueries) {
      const result = await searchCode({
        query,
        limit: Math.max(1, Math.ceil(maxSearchResults / searchQueries.length)),
        maxMatchesPerFile: 2,
      });
      searches.push({ query, matches: result.matches, truncated: result.truncated });
      for (const match of result.matches) {
        if (snippets.length >= maxSnippets) {
          break;
        }
        const key = `${match.file}:${match.line}`;
        if (snippetKeys.has(key)) {
          continue;
        }
        snippetKeys.add(key);
        try {
          snippets.push(await readFileSnippet({
            path: match.file,
            startLine: match.line,
            endLine: match.line,
            contextLines: 3,
            maxChars: 1_600,
          }));
        } catch {
          // Snapshot collection is best effort; direct helper calls still throw.
        }
      }
    }

    return {
      files: listFiles({ limit: maxFiles }),
      searches,
      snippets,
      limits: {
        files: maxFiles,
        searchResults: maxSearchResults,
        snippets: maxSnippets,
      },
      truncated: walk.truncated || files.length > maxFiles || searches.some((search) => search.truncated) || snippets.length >= maxSnippets,
    };
  }

  return {
    repoRoot: root,
    listFiles,
    list_files: listFiles,
    searchCode,
    search_code: searchCode,
    readFileSnippet,
    read_file_snippet: readFileSnippet,
    buildSnapshot,
  };
}

function toInspectionFile(file: SourceFile): CodeInspectionFile {
  return {
    path: file.relativePath,
    size: file.size,
    language: file.language,
    kind: file.kind,
  };
}

async function normalizeRepoRoot(repoRoot: string): Promise<string> {
  const resolved = path.resolve(repoRoot);
  const stats = await fs.stat(resolved);
  if (!stats.isDirectory()) {
    throw new Error(`Repository root must be a directory: ${resolved}`);
  }
  return fs.realpath(resolved);
}

function normalizeQuery(query: string): string {
  const trimmed = query.trim();
  if (!trimmed) {
    throw new Error("search_code query is required.");
  }
  if (trimmed.length > MAX_QUERY_LENGTH) {
    throw new Error(`search_code query exceeds ${MAX_QUERY_LENGTH} characters.`);
  }
  return trimmed;
}

function assertSafeRelativePath(input: string, root: string): string {
  const normalizedInput = input.replace(/\\/g, "/").replace(/^\/+/u, "");
  if (!normalizedInput || path.isAbsolute(input)) {
    throw new Error("Path must be relative to the repository root.");
  }
  const parts = normalizedInput.split("/").filter(Boolean);
  if (parts.some((part) => part === "." || part === ".." || DEFAULT_IGNORES.has(part))) {
    throw new Error(`Path is outside the allowed source set: ${input}`);
  }
  const resolved = path.resolve(root, normalizedInput);
  assertWithinRoot(resolved, root);
  return toPosixPath(path.relative(root, resolved));
}

function assertWithinRoot(targetPath: string, root: string): void {
  const relative = path.relative(root, targetPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Path escapes the repository root.");
  }
}

function boundedInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}
