import type { CodeInspectionRuntime, FileSnippet } from "./codeInspection.js";
import { stableId } from "../shared/text.js";

export type InvestigationCategory =
  | "injection"
  | "command-execution"
  | "secret"
  | "auth-access"
  | "dependency"
  | "database"
  | "api-security"
  | "crypto-data"
  | "config-iac";

export type InvestigationCandidate = {
  candidateId: string;
  category: InvestigationCategory;
  title: string;
  file: string;
  line: number;
  snippet: FileSnippet;
  matchedPattern: string;
  suggestedCwe?: string;
  assignedRole: string;
  priority: number;
};

export type InvestigationTask = {
  taskId: string;
  candidateId: string;
  roleId: string;
  category: InvestigationCategory;
  instruction: string;
  file: string;
  line: number;
  snippet: FileSnippet;
  suggestedCwe?: string;
};

type DiscoveryRule = {
  category: InvestigationCategory;
  title: string;
  query: string;
  assignedRole: string;
  suggestedCwe?: string;
  priority: number;
};

export type CandidateDiscoveryOptions = {
  roleIds?: readonly string[];
  maxCandidates?: number;
  maxCandidatesPerRule?: number;
};

const DEFAULT_MAX_CANDIDATES = 48;
const DEFAULT_MAX_CANDIDATES_PER_RULE = 8;

const DISCOVERY_RULES: readonly DiscoveryRule[] = [
  {
    category: "command-execution",
    title: "Possible command execution",
    query: "exec(",
    assignedRole: "injection-and-execution",
    suggestedCwe: "CWE-78",
    priority: 100,
  },
  {
    category: "command-execution",
    title: "Possible process spawn",
    query: "spawn(",
    assignedRole: "injection-and-execution",
    suggestedCwe: "CWE-78",
    priority: 95,
  },
  {
    category: "command-execution",
    title: "Possible Python subprocess call",
    query: "subprocess.",
    assignedRole: "injection-and-execution",
    suggestedCwe: "CWE-78",
    priority: 95,
  },
  {
    category: "injection",
    title: "Possible dynamic code evaluation",
    query: "eval(",
    assignedRole: "injection-and-execution",
    suggestedCwe: "CWE-95",
    priority: 90,
  },
  {
    category: "injection",
    title: "Possible SQL/query injection",
    query: "SELECT ",
    assignedRole: "injection-and-execution",
    suggestedCwe: "CWE-89",
    priority: 85,
  },
  {
    category: "database",
    title: "Possible raw database query",
    query: "rawQuery",
    assignedRole: "database-and-storage",
    suggestedCwe: "CWE-89",
    priority: 80,
  },
  {
    category: "database",
    title: "Possible direct database execution",
    query: "execute(",
    assignedRole: "database-and-storage",
    suggestedCwe: "CWE-89",
    priority: 78,
  },
  {
    category: "secret",
    title: "Possible hardcoded secret",
    query: "secret",
    assignedRole: "secrets-and-config",
    suggestedCwe: "CWE-798",
    priority: 76,
  },
  {
    category: "secret",
    title: "Possible hardcoded API key",
    query: "api_key",
    assignedRole: "secrets-and-config",
    suggestedCwe: "CWE-798",
    priority: 75,
  },
  {
    category: "auth-access",
    title: "Authentication or token verification path",
    query: "jwt.verify",
    assignedRole: "auth-and-data-flow",
    suggestedCwe: "CWE-287",
    priority: 72,
  },
  {
    category: "auth-access",
    title: "Possible open redirect",
    query: "redirect(",
    assignedRole: "auth-and-data-flow",
    suggestedCwe: "CWE-601",
    priority: 68,
  },
  {
    category: "api-security",
    title: "Possible permissive CORS",
    query: "cors(",
    assignedRole: "auth-and-data-flow",
    suggestedCwe: "CWE-942",
    priority: 64,
  },
  {
    category: "crypto-data",
    title: "Possible weak hash usage",
    query: "md5",
    assignedRole: "secrets-and-config",
    suggestedCwe: "CWE-327",
    priority: 58,
  },
  {
    category: "config-iac",
    title: "Possible debug configuration",
    query: "DEBUG",
    assignedRole: "config-and-iac",
    suggestedCwe: "CWE-489",
    priority: 54,
  },
  {
    category: "config-iac",
    title: "Possible bind-all interface",
    query: "0.0.0.0",
    assignedRole: "config-and-iac",
    suggestedCwe: "CWE-200",
    priority: 52,
  },
  {
    category: "dependency",
    title: "Dependency manifest",
    query: "\"dependencies\"",
    assignedRole: "secrets-and-config",
    priority: 30,
  },
] as const;

export async function discoverInvestigationCandidates(
  runtime: CodeInspectionRuntime,
  options: CandidateDiscoveryOptions = {},
): Promise<InvestigationCandidate[]> {
  const roleIds = new Set(options.roleIds ?? []);
  const maxCandidates = boundedInt(options.maxCandidates, DEFAULT_MAX_CANDIDATES, 1, 200);
  const maxCandidatesPerRule = boundedInt(options.maxCandidatesPerRule, DEFAULT_MAX_CANDIDATES_PER_RULE, 1, 40);
  const candidates: InvestigationCandidate[] = [];
  const seen = new Set<string>();

  for (const rule of DISCOVERY_RULES) {
    if (roleIds.size > 0 && !roleIds.has(rule.assignedRole)) {
      continue;
    }
    const search = await runtime.searchCode({
      query: rule.query,
      limit: maxCandidatesPerRule,
      maxMatchesPerFile: 3,
    });
    for (const match of search.matches) {
      if (candidates.length >= maxCandidates) {
        return sortCandidates(candidates);
      }
      const key = `${rule.category}:${match.file}:${match.line}:${rule.query}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      let snippet: FileSnippet;
      try {
        snippet = await runtime.readFileSnippet({
          path: match.file,
          startLine: match.line,
          endLine: match.line,
          contextLines: 4,
          maxChars: 2_200,
        });
      } catch {
        continue;
      }
      const candidateId = stableId(
        `${rule.category}:${snippet.file}:${match.line}:${rule.query}`,
        "candidate",
      );
      candidates.push({
        candidateId,
        category: rule.category,
        title: rule.title,
        file: snippet.file,
        line: match.line,
        snippet,
        matchedPattern: rule.query,
        ...(rule.suggestedCwe ? { suggestedCwe: rule.suggestedCwe } : {}),
        assignedRole: rule.assignedRole,
        priority: rule.priority,
      });
    }
  }

  return sortCandidates(candidates);
}

export function buildInvestigationTasks(
  candidates: readonly InvestigationCandidate[],
  options: { roleId?: string; maxTasks?: number } = {},
): InvestigationTask[] {
  const maxTasks = boundedInt(options.maxTasks, candidates.length, 1, 200);
  return sortCandidates(candidates)
    .filter((candidate) => !options.roleId || candidate.assignedRole === options.roleId)
    .slice(0, maxTasks)
    .map((candidate) => ({
      taskId: stableId(`${candidate.candidateId}:${candidate.assignedRole}`, "task"),
      candidateId: candidate.candidateId,
      roleId: candidate.assignedRole,
      category: candidate.category,
      instruction: taskInstruction(candidate),
      file: candidate.file,
      line: candidate.line,
      snippet: candidate.snippet,
      ...(candidate.suggestedCwe ? { suggestedCwe: candidate.suggestedCwe } : {}),
    }));
}

export function candidatePromptContext(tasks: readonly InvestigationTask[]): unknown {
  return tasks.map((task) => ({
    taskId: task.taskId,
    candidateId: task.candidateId,
    roleId: task.roleId,
    category: task.category,
    instruction: task.instruction,
    location: {
      file: task.file,
      line: task.line,
    },
    ...(task.suggestedCwe ? { suggestedCwe: task.suggestedCwe } : {}),
    snippet: task.snippet,
  }));
}

function taskInstruction(candidate: InvestigationCandidate): string {
  const base = `Investigate ${candidate.title.toLowerCase()} in ${candidate.file} around line ${candidate.line}.`;
  if (candidate.suggestedCwe) {
    return `${base} Decide whether this is a real ${candidate.suggestedCwe} style vulnerability and cite only the supplied evidence.`;
  }
  return `${base} Decide whether this is a real vulnerability and cite only the supplied evidence.`;
}

function sortCandidates(candidates: readonly InvestigationCandidate[]): InvestigationCandidate[] {
  return [...candidates].sort((left, right) =>
    right.priority - left.priority ||
    left.file.localeCompare(right.file) ||
    left.line - right.line ||
    left.candidateId.localeCompare(right.candidateId),
  );
}

function boundedInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}
