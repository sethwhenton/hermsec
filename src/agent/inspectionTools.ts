import path from "node:path";
import type { SourceFile, SourceLanguage } from "../core/files.js";
import type { CodeInspectionRuntime, FileSnippet } from "./codeInspection.js";
import { inspectionReadOnlyPermission, type ToolContext } from "./permissions.js";
import { createToolRegistry, type HermsecTool, type JsonSchema, type ToolRegistry } from "./toolRegistry.js";

type InspectProjectInput = Record<string, unknown>;
type ListFilesInput = {
  limit?: number;
  pathIncludes?: string;
  kind?: SourceFile["kind"];
  language?: SourceLanguage;
};
type SearchCodeInput = {
  query: string;
  limit?: number;
  maxMatchesPerFile?: number;
  caseSensitive?: boolean;
  pathPrefix?: string;
};
type ReadFileSnippetInput = {
  path: string;
  startLine?: number;
  endLine?: number;
  contextLines?: number;
  maxChars?: number;
};
type ReadManifestInput = {
  path: string;
  maxChars?: number;
};
type ReadDependencyInventoryInput = {
  limit?: number;
  maxCharsPerManifest?: number;
};

const objectSchema = (properties: Record<string, unknown>, required: string[] = []): JsonSchema => ({
  type: "object",
  properties,
  ...(required.length > 0 ? { required } : {}),
  additionalProperties: false,
});

const integerSchema = (minimum: number, maximum: number): JsonSchema => ({
  type: "integer",
  minimum,
  maximum,
});

const sourceKinds: SourceFile["kind"][] = ["source", "manifest", "lockfile", "config", "text"];
const sourceLanguages: SourceLanguage[] = [
  "javascript", "typescript", "python", "java", "jsp", "php", "go", "rust", "ruby",
  "c", "cpp", "csharp", "kotlin", "swift", "dart", "html", "vue", "svelte",
  "terraform", "json", "xml", "yaml", "toml", "properties", "gradle", "text", "unknown",
];

export function createInspectionToolRegistry(runtime: CodeInspectionRuntime): ToolRegistry {
  return createToolRegistry(runtime.repoRoot, [
    inspectProjectTool(runtime),
    listFilesTool(runtime),
    searchCodeTool(runtime),
    readFileSnippetTool(runtime),
    readManifestTool(runtime),
    readDependencyInventoryTool(runtime),
  ]);
}

function inspectProjectTool(runtime: CodeInspectionRuntime): HermsecTool<InspectProjectInput, Record<string, unknown>> {
  return {
    name: "inspect_project",
    description: "Summarize indexed languages, file kinds, manifests, lockfiles, ignored paths, and coverage limits without reading source content.",
    inputSchema: objectSchema({}),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      return strictObject(input, "inspect_project", []);
    },
    validateOutput: objectOutput("inspect_project"),
    async run(_input, context) {
      throwIfAborted(context);
      const files = runtime.listFiles({ limit: 5_000 });
      return {
        repositoryName: path.basename(runtime.repoRoot),
        indexedFiles: runtime.profile.indexedFiles,
        listedFiles: files.length,
        deniedSecretFiles: runtime.profile.deniedSecretFiles,
        languages: countBy(files.map((file) => file.language)),
        kinds: countBy(files.map((file) => file.kind)),
        manifests: files.filter((file) => file.kind === "manifest").slice(0, 100).map((file) => file.path),
        lockfiles: files.filter((file) => file.kind === "lockfile").slice(0, 100).map((file) => file.path),
        ignoredDirectories: runtime.profile.ignoredDirectories,
        truncated: runtime.profile.truncated || runtime.profile.indexedFiles > files.length,
      };
    },
  };
}

function listFilesTool(runtime: CodeInspectionRuntime): HermsecTool<ListFilesInput, Record<string, unknown>> {
  return {
    name: "list_files",
    description: "List bounded, non-secret repository files with optional language, kind, or path filters.",
    inputSchema: objectSchema({
      limit: integerSchema(1, 500),
      pathIncludes: { type: "string", maxLength: 200 },
      kind: { type: "string", enum: sourceKinds },
      language: { type: "string", enum: sourceLanguages },
    }),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      const value = strictObject(input, "list_files", ["limit", "pathIncludes", "kind", "language"]);
      return {
        ...optionalInteger(value, "limit", 1, 500),
        ...optionalString(value, "pathIncludes", 200),
        ...optionalEnum(value, "kind", sourceKinds),
        ...optionalEnum(value, "language", sourceLanguages),
      };
    },
    validateOutput: objectOutput("list_files"),
    async run(input, context) {
      throwIfAborted(context);
      const limit = input.limit ?? 200;
      const files = runtime.listFiles({
        limit: limit + 1,
        ...(input.pathIncludes ? { pathIncludes: input.pathIncludes } : {}),
        ...(input.kind ? { kind: input.kind } : {}),
        ...(input.language ? { language: input.language } : {}),
      });
      return {
        files: files.slice(0, limit),
        truncated: files.length > limit,
      };
    },
  };
}

function searchCodeTool(runtime: CodeInspectionRuntime): HermsecTool<SearchCodeInput, Record<string, unknown>> {
  return {
    name: "search_code",
    description: "Search indexed source text for one literal query and return bounded, redacted line previews.",
    inputSchema: objectSchema({
      query: { type: "string", minLength: 1, maxLength: 200 },
      limit: integerSchema(1, 200),
      maxMatchesPerFile: integerSchema(1, 20),
      caseSensitive: { type: "boolean" },
      pathPrefix: { type: "string", maxLength: 300 },
    }, ["query"]),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      const value = strictObject(input, "search_code", [
        "query", "limit", "maxMatchesPerFile", "caseSensitive", "pathPrefix",
      ]);
      return {
        query: requiredString(value, "query", 200),
        ...optionalInteger(value, "limit", 1, 200),
        ...optionalInteger(value, "maxMatchesPerFile", 1, 20),
        ...optionalBoolean(value, "caseSensitive"),
        ...optionalString(value, "pathPrefix", 300),
      };
    },
    validateOutput: objectOutput("search_code"),
    async run(input, context) {
      return runtime.searchCode({
        ...input,
        ...(context.signal ? { signal: context.signal } : {}),
      });
    },
  };
}

function readFileSnippetTool(runtime: CodeInspectionRuntime): HermsecTool<ReadFileSnippetInput, FileSnippet> {
  return {
    name: "read_file_snippet",
    description: "Read a bounded, line-numbered, redacted snippet from one indexed non-secret repository file.",
    inputSchema: objectSchema({
      path: { type: "string", minLength: 1, maxLength: 500 },
      startLine: integerSchema(1, 2_000_000),
      endLine: integerSchema(1, 2_000_000),
      contextLines: integerSchema(0, 20),
      maxChars: integerSchema(200, 20_000),
    }, ["path"]),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      const value = strictObject(input, "read_file_snippet", [
        "path", "startLine", "endLine", "contextLines", "maxChars",
      ]);
      return {
        path: requiredString(value, "path", 500),
        ...optionalInteger(value, "startLine", 1, 2_000_000),
        ...optionalInteger(value, "endLine", 1, 2_000_000),
        ...optionalInteger(value, "contextLines", 0, 20),
        ...optionalInteger(value, "maxChars", 200, 20_000),
      };
    },
    validateOutput(output) {
      const value = strictObject(output, "read_file_snippet output", [
        "file", "startLine", "endLine", "text", "truncated",
      ]);
      return {
        file: requiredString(value, "file", 1_000),
        startLine: requiredInteger(value, "startLine", 1, 2_000_000),
        endLine: requiredInteger(value, "endLine", 1, 2_000_000),
        text: requiredString(value, "text", 30_000, true),
        truncated: requiredBoolean(value, "truncated"),
      };
    },
    async run(input, context) {
      return runtime.readFileSnippet({
        ...input,
        ...(context.signal ? { signal: context.signal } : {}),
      });
    },
  };
}

function readManifestTool(runtime: CodeInspectionRuntime): HermsecTool<ReadManifestInput, Record<string, unknown>> {
  return {
    name: "read_manifest",
    description: "Read one bounded, redacted dependency manifest. Lockfiles and secret-bearing configuration are not accepted.",
    inputSchema: objectSchema({
      path: { type: "string", minLength: 1, maxLength: 500 },
      maxChars: integerSchema(500, 12_000),
    }, ["path"]),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      const value = strictObject(input, "read_manifest", ["path", "maxChars"]);
      return {
        path: requiredString(value, "path", 500),
        ...optionalInteger(value, "maxChars", 500, 12_000),
      };
    },
    validateOutput: objectOutput("read_manifest"),
    async run(input, context) {
      const manifest = runtime.listFiles({ kind: "manifest", limit: 5_000 })
        .find((file) => file.path === normalizeRelative(input.path));
      if (!manifest) {
        throw new Error("read_manifest path must identify an indexed manifest.");
      }
      const snippet = await runtime.readFileSnippet({
        path: manifest.path,
        startLine: 1,
        endLine: 160,
        maxChars: input.maxChars ?? 6_000,
        ...(context.signal ? { signal: context.signal } : {}),
      });
      return {
        manifest: manifest.path,
        language: manifest.language,
        snippet,
      };
    },
  };
}

function readDependencyInventoryTool(
  runtime: CodeInspectionRuntime,
): HermsecTool<ReadDependencyInventoryInput, Record<string, unknown>> {
  return {
    name: "read_dependency_inventory",
    description: "Summarize dependency manifests and lockfile presence, with bounded redacted manifest excerpts.",
    inputSchema: objectSchema({
      limit: integerSchema(1, 20),
      maxCharsPerManifest: integerSchema(500, 5_000),
    }),
    outputSchema: { type: "object" },
    permission: inspectionReadOnlyPermission(),
    validateInput(input) {
      const value = strictObject(input, "read_dependency_inventory", ["limit", "maxCharsPerManifest"]);
      return {
        ...optionalInteger(value, "limit", 1, 20),
        ...optionalInteger(value, "maxCharsPerManifest", 500, 5_000),
      };
    },
    validateOutput: objectOutput("read_dependency_inventory"),
    async run(input, context) {
      const limit = input.limit ?? 8;
      const maxChars = input.maxCharsPerManifest ?? 2_500;
      const manifests = runtime.listFiles({ kind: "manifest", limit: limit + 1 });
      const lockfiles = runtime.listFiles({ kind: "lockfile", limit: 100 });
      const excerpts: Array<Record<string, unknown>> = [];

      for (const manifest of manifests.slice(0, limit)) {
        throwIfAborted(context);
        const snippet = await runtime.readFileSnippet({
          path: manifest.path,
          startLine: 1,
          endLine: 120,
          maxChars,
          ...(context.signal ? { signal: context.signal } : {}),
        });
        excerpts.push({
          path: manifest.path,
          language: manifest.language,
          snippet,
        });
      }
      return {
        manifests: excerpts,
        manifestListTruncated: manifests.length > limit,
        lockfiles: lockfiles.map((file) => ({
          path: file.path,
          size: file.size,
        })),
      };
    },
  };
}

function strictObject(
  input: unknown,
  label: string,
  allowedKeys: readonly string[],
): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} input must be a JSON object.`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} input must be a plain JSON object.`);
  }
  const value = input as Record<string, unknown>;
  const unexpected = Object.keys(value).filter((key) => !allowedKeys.includes(key));
  if (unexpected.length > 0) {
    throw new Error(`${label} input contains unsupported field: ${unexpected[0]}`);
  }
  return value;
}

function objectOutput(label: string): (output: unknown) => Record<string, unknown> {
  return (output) => {
    if (
      output === null ||
      typeof output !== "object" ||
      Array.isArray(output) ||
      (Object.getPrototypeOf(output) !== Object.prototype && Object.getPrototypeOf(output) !== null)
    ) {
      throw new Error(`${label} returned an invalid output object.`);
    }
    return output as Record<string, unknown>;
  };
}

function requiredString(
  value: Record<string, unknown>,
  key: string,
  maxLength: number,
  allowEmpty = false,
): string {
  if (!Object.hasOwn(value, key)) {
    throw new Error(`${key} is required.`);
  }
  const result = value[key];
  if (typeof result !== "string" || (!allowEmpty && !result.trim()) || result.length > maxLength) {
    throw new Error(`${key} must be a string no longer than ${maxLength} characters.`);
  }
  return result;
}

function optionalString(
  value: Record<string, unknown>,
  key: string,
  maxLength: number,
): Record<string, string> {
  if (!Object.hasOwn(value, key) || value[key] === undefined) {
    return {};
  }
  return { [key]: requiredString(value, key, maxLength) };
}

function requiredInteger(
  value: Record<string, unknown>,
  key: string,
  minimum: number,
  maximum: number,
): number {
  if (!Object.hasOwn(value, key)) {
    throw new Error(`${key} is required.`);
  }
  const result = value[key];
  if (!Number.isInteger(result) || (result as number) < minimum || (result as number) > maximum) {
    throw new Error(`${key} must be an integer between ${minimum} and ${maximum}.`);
  }
  return result as number;
}

function optionalInteger(
  value: Record<string, unknown>,
  key: string,
  minimum: number,
  maximum: number,
): Record<string, number> {
  if (!Object.hasOwn(value, key) || value[key] === undefined) {
    return {};
  }
  return { [key]: requiredInteger(value, key, minimum, maximum) };
}

function requiredBoolean(value: Record<string, unknown>, key: string): boolean {
  if (!Object.hasOwn(value, key)) {
    throw new Error(`${key} is required.`);
  }
  if (typeof value[key] !== "boolean") {
    throw new Error(`${key} must be a boolean.`);
  }
  return value[key] as boolean;
}

function optionalBoolean(value: Record<string, unknown>, key: string): Record<string, boolean> {
  if (!Object.hasOwn(value, key) || value[key] === undefined) {
    return {};
  }
  return { [key]: requiredBoolean(value, key) };
}

function optionalEnum<T extends string>(
  value: Record<string, unknown>,
  key: string,
  values: readonly T[],
): Record<string, T> {
  if (!Object.hasOwn(value, key) || value[key] === undefined) {
    return {};
  }
  if (typeof value[key] !== "string" || !values.includes(value[key] as T)) {
    throw new Error(`${key} must be one of: ${values.join(", ")}.`);
  }
  return { [key]: value[key] as T };
}

function normalizeRelative(input: string): string {
  return input.replace(/\\/gu, "/").replace(/^\.\/+/u, "");
}

function countBy(values: readonly string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function throwIfAborted(context: ToolContext): void {
  if (context.signal?.aborted) {
    throw context.signal.reason instanceof Error ? context.signal.reason : new Error("Tool call was aborted.");
  }
}
