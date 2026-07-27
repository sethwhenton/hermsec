import type { BigIntStats } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORES, walkSourceTree, type SourceFile } from "../core/files.js";
import { toPosixPath } from "../shared/paths.js";
import { clampText } from "../shared/text.js";
import { redactForModel } from "./redaction.js";

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
  signal?: AbortSignal;
}) => Promise<{ matches: CodeSearchResult[]; truncated: boolean }>;

export type ReadFileSnippetHelper = (input: {
  path: string;
  startLine?: number;
  endLine?: number;
  contextLines?: number;
  maxChars?: number;
  signal?: AbortSignal;
}) => Promise<FileSnippet>;

export type CodeInspectionRuntime = {
  repoRoot: string;
  profile: {
    indexedFiles: number;
    deniedSecretFiles: number;
    ignoredDirectories: Array<{ name: string; count: number }>;
    truncated: boolean;
  };
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
const MAX_SECRET_IDENTITY_SCAN_ENTRIES = 50_000;
const SECRET_FILE_NAMES = new Set([
  ".npmrc",
  ".yarnrc",
  ".pypirc",
  ".netrc",
  ".dockercfg",
  "credentials",
  "credentials.json",
  "service-account.json",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
]);
const SECRET_FILE_EXTENSIONS = new Set([
  ".key",
  ".pem",
  ".p12",
  ".pfx",
  ".jks",
  ".keystore",
]);

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
  const maxTextFileBytes = boundedInt(options.maxTextFileBytes, DEFAULT_MAX_TEXT_FILE_BYTES, 1_000, 5_000_000);
  const maxLockfileBytes = boundedInt(options.maxLockfileBytes, DEFAULT_MAX_LOCKFILE_BYTES, 1_000, 10_000_000);
  const deniedSecretSourceFiles = walk.files.filter((file) => isSecretFilePath(file.relativePath));
  const deniedSecretFiles = deniedSecretSourceFiles.length;
  const indexedDeniedSecretIdentities = await collectIndexedSecretFileIdentities(
    deniedSecretSourceFiles,
    root,
  );
  const files = walk.files.filter((file) => !isSecretFilePath(file.relativePath));
  const indexedFileIdentities = await collectIndexedFileIdentities(files, root);
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
    throwIfAborted(input.signal);
    const query = normalizeQuery(input.query);
    const limit = boundedInt(input.limit, DEFAULT_SEARCH_LIMIT, 1, 500);
    const maxMatchesPerFile = boundedInt(input.maxMatchesPerFile, DEFAULT_MATCHES_PER_FILE, 1, 25);
    const pathPrefix = input.pathPrefix ? assertSafeRelativePath(input.pathPrefix, root) : undefined;
    const needle = input.caseSensitive ? query : query.toLowerCase();
    const matches: CodeSearchResult[] = [];
    let searchedFiles = 0;

    for (const file of files) {
      throwIfAborted(input.signal);
      if (pathPrefix && file.relativePath !== pathPrefix && !file.relativePath.startsWith(`${pathPrefix}/`)) {
        continue;
      }
      if (searchedFiles >= maxSearchFiles) {
        return { matches, truncated: true };
      }
      searchedFiles += 1;

      let content: string;
      try {
        content = await readAllowedTextFile(
          file,
          root,
          indexedFileIdentities.get(file.relativePath),
          indexedDeniedSecretIdentities,
          readLimitFor(file, maxTextFileBytes, maxLockfileBytes),
          input.signal,
        );
      } catch (error) {
        if (input.signal?.aborted) {
          throw error;
        }
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
          preview: clampText(String(redactForModel(line).value), 240),
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
    throwIfAborted(input.signal);
    const relativePath = assertSafeRelativePath(input.path, root);
    assertNotSecretFilePath(relativePath);
    const file = fileByPath.get(relativePath);
    if (!file) {
      throw new Error(`File is not in the allowed source set: ${relativePath}`);
    }
    const content = await readAllowedTextFile(
      file,
      root,
      indexedFileIdentities.get(file.relativePath),
      indexedDeniedSecretIdentities,
      readLimitFor(file, maxTextFileBytes, maxLockfileBytes),
      input.signal,
    );
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
      selectedLines.push(`${lineNumber}: ${rawLine}`);
      if (selectedLines.join("\n").length > maxChars) {
        truncated = true;
        break;
      }
    }
    const text = String(redactForModel(selectedLines.join("\n")).value);
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
    profile: {
      indexedFiles: files.length,
      deniedSecretFiles,
      ignoredDirectories: walk.ignoredDirectories,
      truncated: walk.truncated,
    },
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

export function isSecretFilePath(input: string): boolean {
  const normalized = toPosixPath(input).toLowerCase();
  return normalized.split("/").some((segment) => {
    if (segment.startsWith(".env")) {
      return true;
    }
    if (SECRET_FILE_NAMES.has(segment) || SECRET_FILE_EXTENSIONS.has(path.posix.extname(segment))) {
      return true;
    }
    return /^(?:secrets?|credentials?)(?:[._-].*)?$/iu.test(segment);
  });
}

function assertNotSecretFilePath(input: string): void {
  if (isSecretFilePath(input)) {
    throw new Error("Secret-bearing files are denied from model inspection.");
  }
}

function assertWithinRoot(targetPath: string, root: string): void {
  const relative = path.relative(root, targetPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Path escapes the repository root.");
  }
}

async function readAllowedTextFile(
  file: SourceFile,
  root: string,
  indexedFileIdentity: string | undefined,
  indexedDeniedSecretIdentities: ReadonlySet<string>,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<string> {
  assertNotSecretFilePath(file.relativePath);
  throwIfAborted(signal);

  const firstRealPath = await fs.realpath(file.absolutePath);
  assertWithinRoot(firstRealPath, root);
  assertNotSecretFilePath(toPosixPath(path.relative(root, firstRealPath)));
  const handle = await fs.open(firstRealPath, "r");
  try {
    const secondRealPath = await fs.realpath(file.absolutePath);
    assertWithinRoot(secondRealPath, root);
    assertNotSecretFilePath(toPosixPath(path.relative(root, secondRealPath)));
    if (!samePath(firstRealPath, secondRealPath)) {
      throw new Error("File target changed during inspection.");
    }
    const stats = await handle.stat({ bigint: true });
    if (!stats.isFile()) {
      throw new Error(`Inspection target is not a regular file: ${file.relativePath}`);
    }
    if (!indexedFileIdentity || fileIdentity(stats) !== indexedFileIdentity) {
      throw new Error("File identity changed after the inspection index was created.");
    }
    if (stats.size > BigInt(maxBytes)) {
      throw new Error(`Inspection target exceeds the allowed byte limit: ${file.relativePath}`);
    }
    if (indexedDeniedSecretIdentities.has(fileIdentity(stats))) {
      throw new Error("Secret-bearing file aliases are denied from model inspection.");
    }
    if (stats.nlink > 1n) {
      const deniedIdentities = await collectDeniedSecretFileIdentities(root, signal);
      if (deniedIdentities.has(fileIdentity(stats))) {
        throw new Error("Secret-bearing file aliases are denied from model inspection.");
      }
    }
    throwIfAborted(signal);
    const buffer = await handle.readFile();
    throwIfAborted(signal);
    if (buffer.byteLength > maxBytes) {
      throw new Error(`Inspection target exceeds the allowed byte limit: ${file.relativePath}`);
    }
    if (buffer.includes(0)) {
      throw new Error(`Skipping binary-like file: ${file.relativePath}`);
    }
    const content = buffer.toString("utf8");
    assertSafeInspectionContent(content);
    return content;
  } finally {
    await handle.close();
  }
}

async function collectIndexedFileIdentities(
  files: readonly SourceFile[],
  root: string,
): Promise<Map<string, string>> {
  const identities = new Map<string, string>();
  for (const file of files) {
    try {
      const resolved = await fs.realpath(file.absolutePath);
      assertWithinRoot(resolved, root);
      assertNotSecretFilePath(toPosixPath(path.relative(root, resolved)));
      const stats = await fs.stat(resolved, { bigint: true });
      if (stats.isFile()) {
        identities.set(file.relativePath, fileIdentity(stats));
      }
    } catch {
      // A file whose identity cannot be captured is listed but remains unreadable.
    }
  }
  return identities;
}

async function collectIndexedSecretFileIdentities(
  files: readonly SourceFile[],
  root: string,
): Promise<Set<string>> {
  const identities = new Set<string>();
  for (const file of files) {
    try {
      const resolved = await fs.realpath(file.absolutePath);
      assertWithinRoot(resolved, root);
      const stats = await fs.stat(resolved, { bigint: true });
      if (stats.isFile()) {
        identities.add(fileIdentity(stats));
      }
    } catch {
      // Denied files are never opened for content; inaccessible entries remain denied by path.
    }
  }
  return identities;
}

async function collectDeniedSecretFileIdentities(
  root: string,
  signal?: AbortSignal,
): Promise<Set<string>> {
  const identities = new Set<string>();
  const pending = [root];
  let inspectedEntries = 0;

  while (pending.length > 0) {
    throwIfAborted(signal);
    const directory = pending.pop();
    if (!directory) {
      break;
    }
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      throwIfAborted(signal);
      inspectedEntries += 1;
      if (inspectedEntries > MAX_SECRET_IDENTITY_SCAN_ENTRIES) {
        throw new Error("Secret-file identity scan exceeded its safety limit.");
      }
      const absolutePath = path.join(directory, entry.name);
      const relativePath = toPosixPath(path.relative(root, absolutePath));
      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORES.has(entry.name)) {
          pending.push(absolutePath);
        }
        continue;
      }
      if ((!entry.isFile() && !entry.isSymbolicLink()) || !isSecretFilePath(relativePath)) {
        continue;
      }
      try {
        const resolved = await fs.realpath(absolutePath);
        assertWithinRoot(resolved, root);
        const stats = await fs.stat(resolved, { bigint: true });
        if (stats.isFile()) {
          identities.add(fileIdentity(stats));
        }
      } catch {
        // An unreadable or out-of-root secret alias cannot authorize an inspection read.
      }
    }
  }
  return identities;
}

function fileIdentity(stats: BigIntStats): string {
  return `${stats.dev.toString()}:${stats.ino.toString()}`;
}

function assertSafeInspectionContent(content: string): void {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(content)) {
    throw new Error("Secret-bearing file content is denied from model inspection.");
  }

  const meaningfulLines = content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .slice(0, 2_000);
  let assignments = 0;
  let sensitiveAssignments = 0;
  for (const line of meaningfulLines) {
    const match = /^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*.+$/u.exec(line);
    if (!match) {
      continue;
    }
    assignments += 1;
    if (
      /(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL|DATABASE_URL|REDIS_URL|DSN|URI)$/u
        .test(match[1] ?? "")
    ) {
      sensitiveAssignments += 1;
    }
  }
  if (
    sensitiveAssignments > 0 &&
    assignments >= Math.max(1, Math.ceil(meaningfulLines.length / 2))
  ) {
    throw new Error("Environment-like secret content is denied from model inspection.");
  }
}

function readLimitFor(file: SourceFile, maxTextFileBytes: number, maxLockfileBytes: number): number {
  return file.kind === "lockfile" ? maxLockfileBytes : maxTextFileBytes;
}

function samePath(left: string, right: string): boolean {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Inspection was aborted.");
  }
}

function boundedInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}
