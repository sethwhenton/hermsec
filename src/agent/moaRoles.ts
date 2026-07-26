import type {
  ProjectCapability,
  ProjectProfile,
} from "./projectProfiler.js";

export type MoaLevel = "low" | "high";

export type MoaCoverageCategory =
  | "authentication"
  | "authorization"
  | "cryptography"
  | "dependencies"
  | "deployment"
  | "injection"
  | "platform-configuration"
  | "request-security"
  | "sensitive-data"
  | "storage"
  | "supply-chain"
  | "unsafe-execution";

export type MoaRoleId =
  | "injection-and-execution"
  | "identity-and-request-security"
  | "sensitive-data-and-cryptography"
  | "dependencies-and-supply-chain"
  | "platform-storage-and-deployment";

export type MoaRoleDefinition = {
  id: MoaRoleId;
  order: number;
  label: string;
  focus: string;
  categories: readonly MoaCoverageCategory[];
  searchObjectives: readonly string[];
  capabilityWeights: Readonly<Partial<Record<ProjectCapability, number>>>;
  pathHints: readonly string[];
};

export type MoaRoleScore = {
  role: MoaRoleDefinition;
  score: number;
  reasons: string[];
};

export type MoaRolePlan = {
  level: MoaLevel;
  roles: MoaRoleScore[];
  rankedRoles: MoaRoleScore[];
};

export const MOA_ROLES: readonly MoaRoleDefinition[] = [
  {
    id: "injection-and-execution",
    order: 0,
    label: "Injection and execution specialist",
    focus: "Trace untrusted input into interpreters, queries, templates, file paths, deserializers, and process execution.",
    categories: ["injection", "unsafe-execution"],
    searchObjectives: [
      "command and argument construction",
      "SQL and datastore query construction",
      "template and browser output sinks",
      "deserialization and dynamic evaluation",
      "server-side request and path traversal flows",
    ],
    capabilityWeights: {
      "http-api": 5,
      database: 7,
      "template-rendering": 6,
      "process-execution": 10,
      "file-upload": 4,
    },
    pathHints: ["api", "controllers", "db", "models", "routes", "templates", "views"],
  },
  {
    id: "identity-and-request-security",
    order: 1,
    label: "Identity and request security specialist",
    focus: "Trace authentication, authorization, sessions, tokens, CSRF, CORS, redirects, and trust-boundary decisions.",
    categories: ["authentication", "authorization", "request-security"],
    searchObjectives: [
      "authentication and authorization guards",
      "session and cookie configuration",
      "JWT and OAuth validation",
      "CSRF, CORS, redirect, and proxy trust behavior",
    ],
    capabilityWeights: {
      "http-api": 7,
      authentication: 11,
      "sensitive-config": 2,
      cryptography: 2,
    },
    pathHints: ["api", "auth", "controllers", "login", "middleware", "routes", "session"],
  },
  {
    id: "sensitive-data-and-cryptography",
    order: 2,
    label: "Sensitive data and cryptography specialist",
    focus: "Inspect secrets, credentials, personal data, logging, encryption, hashing, signing, and key lifecycle controls.",
    categories: ["sensitive-data", "cryptography"],
    searchObjectives: [
      "hardcoded or exposed credentials",
      "sensitive values in logs and errors",
      "weak hashes, ciphers, randomness, and TLS",
      "key storage and rotation",
    ],
    capabilityWeights: {
      authentication: 4,
      "cloud-storage": 4,
      cryptography: 11,
      database: 3,
      "sensitive-config": 9,
    },
    pathHints: ["config", "crypto", "keys", "logs", "models", "secrets", "settings", "storage"],
  },
  {
    id: "dependencies-and-supply-chain",
    order: 3,
    label: "Dependencies and supply-chain specialist",
    focus: "Inspect dependency declarations, lockfiles, package scripts, CI acquisition paths, and provenance controls.",
    categories: ["dependencies", "supply-chain"],
    searchObjectives: [
      "unlocked or ambiguous dependency resolution",
      "risky package scripts and remote dependencies",
      "outdated or vulnerable direct dependencies",
      "CI and release provenance",
    ],
    capabilityWeights: {
      "dependency-management": 12,
      ci: 5,
      container: 2,
    },
    pathHints: ["package", "requirements", "lock", "workflow", "ci", "gradle", "cargo"],
  },
  {
    id: "platform-storage-and-deployment",
    order: 4,
    label: "Platform, storage, and deployment specialist",
    focus: "Inspect storage exposure, cloud permissions, containers, CI, infrastructure-as-code, and production hardening.",
    categories: ["platform-configuration", "storage", "deployment"],
    searchObjectives: [
      "public storage and broad cloud permissions",
      "container privilege and image hardening",
      "infrastructure and CI permissions",
      "unsafe production defaults and network exposure",
    ],
    capabilityWeights: {
      ci: 7,
      "cloud-storage": 10,
      container: 10,
      database: 2,
      "infrastructure-as-code": 12,
      "sensitive-config": 3,
    },
    pathHints: ["docker", "helm", "k8s", "kubernetes", "storage", "terraform", "workflow"],
  },
] as const;

export function rankMoaRoles(profile: ProjectProfile): MoaRoleScore[] {
  const capabilities = new Map(
    profile.capabilities.map((signal) => [signal.id, signal]),
  );
  return MOA_ROLES
    .map((role) => {
      const reasons: string[] = [];
      let score = 0;
      for (const [capability, weight] of Object.entries(role.capabilityWeights) as Array<
        [ProjectCapability, number]
      >) {
        const signal = capabilities.get(capability);
        if (!signal) {
          continue;
        }
        score += weight;
        reasons.push(
          `${capability} (+${weight}; ${signal.evidence.length} signal${signal.evidence.length === 1 ? "" : "s"})`,
        );
      }
      const pathMatches = profile.files.filter((file) => {
        const lower = file.path.toLowerCase();
        return role.pathHints.some((hint) => lower.includes(hint));
      }).length;
      if (pathMatches > 0) {
        const pathScore = Math.min(4, pathMatches);
        score += pathScore;
        reasons.push(`relevant paths (+${pathScore}; ${pathMatches} match${pathMatches === 1 ? "" : "es"})`);
      }
      return {
        role,
        score,
        reasons: reasons.sort(),
      };
    })
    .sort(compareRoleScores);
}

export function selectMoaRoles(
  profile: ProjectProfile,
  level: MoaLevel,
): MoaRolePlan {
  const rankedRoles = rankMoaRoles(profile);
  const selectedIds = new Set(
    level === "high"
      ? MOA_ROLES.map((role) => role.id)
      : rankedRoles.slice(0, 3).map((entry) => entry.role.id),
  );
  const roles = level === "high"
    ? MOA_ROLES.map((role) => rankedRoles.find((entry) => entry.role.id === role.id)!)
    : rankedRoles.filter((entry) => selectedIds.has(entry.role.id)).slice(0, 3);
  return {
    level,
    roles: roles.map(cloneRoleScore),
    rankedRoles: rankedRoles.map(cloneRoleScore),
  };
}

export function moaRoleById(roleId: MoaRoleId): MoaRoleDefinition {
  const role = MOA_ROLES.find((candidate) => candidate.id === roleId);
  if (!role) {
    throw new Error(`Unknown MoA role: ${roleId}`);
  }
  return role;
}

function compareRoleScores(left: MoaRoleScore, right: MoaRoleScore): number {
  return right.score - left.score || left.role.order - right.role.order;
}

function cloneRoleScore(entry: MoaRoleScore): MoaRoleScore {
  return {
    role: entry.role,
    score: entry.score,
    reasons: [...entry.reasons],
  };
}
