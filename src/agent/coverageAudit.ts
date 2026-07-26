import {
  MOA_ROLES,
  moaRoleById,
  type MoaCoverageCategory,
  type MoaRoleId,
} from "./moaRoles.js";
import type { ProjectProfile } from "./projectProfiler.js";

export type MoaRoleExecutionStatus =
  | "completed"
  | "partial"
  | "failed"
  | "skipped";

export type MoaRoleExecutionCoverage = {
  roleId: MoaRoleId;
  status: MoaRoleExecutionStatus;
  inspectedFiles: readonly string[];
  coveredCategories: readonly MoaCoverageCategory[];
};

export type MoaCoverageAudit = {
  status: "complete" | "partial" | "degraded";
  languages: {
    detected: string[];
    supported: string[];
    unsupported: string[];
    inspected: string[];
    uninspected: string[];
  };
  files: {
    total: number;
    inspected: string[];
    uninspected: string[];
    unknownReportedFiles: string[];
    coverageRatio: number;
  };
  categories: {
    expected: MoaCoverageCategory[];
    covered: MoaCoverageCategory[];
    missing: MoaCoverageCategory[];
  };
  roles: {
    selected: MoaRoleId[];
    completed: MoaRoleId[];
    partial: MoaRoleId[];
    failed: MoaRoleId[];
    skipped: MoaRoleId[];
    notRun: MoaRoleId[];
  };
  gapFill?: MoaGapFillRecommendation;
};

export type MoaGapFillRecommendation = {
  bounded: true;
  maxAdditionalRounds: 1;
  roleId: MoaRoleId;
  files: string[];
  categories: MoaCoverageCategory[];
  reason: string;
};

export function auditMoaCoverage(input: {
  profile: ProjectProfile;
  selectedRoleIds: readonly MoaRoleId[];
  roleExecutions: readonly MoaRoleExecutionCoverage[];
  supportedLanguages?: readonly string[];
  maxGapFillFiles?: number;
  maxGapFillCategories?: number;
}): MoaCoverageAudit {
  const selectedRoleIds = canonicalRoleIds(input.selectedRoleIds);
  const executions = canonicalExecutions(input.roleExecutions);
  const executionByRole = new Map(executions.map((execution) => [execution.roleId, execution]));
  const contributingExecutions = executions.filter((execution) =>
    selectedRoleIds.includes(execution.roleId)
    && (execution.status === "completed" || execution.status === "partial")
  );
  const knownFiles = new Set(input.profile.files.map((file) => file.path));
  const reportedFiles = new Set(
    contributingExecutions.flatMap((execution) => [...execution.inspectedFiles]),
  );
  const inspectedFiles = [...reportedFiles].filter((file) => knownFiles.has(file)).sort();
  const unknownReportedFiles = [...reportedFiles].filter((file) => !knownFiles.has(file)).sort();
  const uninspectedFiles = input.profile.files
    .map((file) => file.path)
    .filter((file) => !reportedFiles.has(file))
    .sort();
  const detectedLanguages = input.profile.languages
    .filter((language) => language.sourceFileCount > 0)
    .map((language) => language.language)
    .sort();
  const supportedLanguageSet = new Set(
    (input.supportedLanguages ?? detectedLanguages).map((language) => language.toLowerCase()),
  );
  const supportedLanguages = detectedLanguages.filter((language) =>
    supportedLanguageSet.has(language.toLowerCase())
  );
  const unsupportedLanguages = detectedLanguages.filter((language) =>
    !supportedLanguageSet.has(language.toLowerCase())
  );
  const inspectedLanguages = [...new Set(
    input.profile.files
      .filter((file) => reportedFiles.has(file.path) && file.kind === "source")
      .map((file) => file.language),
  )].sort();
  const uninspectedLanguages = supportedLanguages.filter((language) =>
    !inspectedLanguages.includes(language as ProjectProfile["files"][number]["language"])
  );
  const expectedCategories = [...new Set(
    selectedRoleIds.flatMap((roleId) => [...moaRoleById(roleId).categories]),
  )].sort();
  const coveredCategories = [...new Set(
    contributingExecutions
      .flatMap((execution) => [...execution.coveredCategories]),
  )]
    .filter((category) => expectedCategories.includes(category))
    .sort();
  const missingCategories = expectedCategories.filter((category) =>
    !coveredCategories.includes(category)
  );

  const roles = {
    selected: selectedRoleIds,
    completed: rolesWithStatus(selectedRoleIds, executionByRole, "completed"),
    partial: rolesWithStatus(selectedRoleIds, executionByRole, "partial"),
    failed: rolesWithStatus(selectedRoleIds, executionByRole, "failed"),
    skipped: rolesWithStatus(selectedRoleIds, executionByRole, "skipped"),
    notRun: selectedRoleIds.filter((roleId) => !executionByRole.has(roleId)),
  };
  const gapFill = recommendGapFill({
    profile: input.profile,
    selectedRoleIds,
    executionByRole,
    uninspectedFiles,
    missingCategories,
    maxFiles: boundedInt(input.maxGapFillFiles, 6, 1, 20),
    maxCategories: boundedInt(input.maxGapFillCategories, 3, 1, 8),
  });
  const hasRoleFailure = roles.failed.length > 0
    || roles.skipped.length > 0
    || roles.notRun.length > 0;
  const status = hasRoleFailure
    || unsupportedLanguages.length > 0
    || unknownReportedFiles.length > 0
    ? "degraded" as const
    : missingCategories.length > 0 || uninspectedFiles.length > 0 || roles.partial.length > 0
      ? "partial" as const
      : "complete" as const;
  const totalFiles = input.profile.files.length;

  return {
    status,
    languages: {
      detected: detectedLanguages,
      supported: supportedLanguages,
      unsupported: unsupportedLanguages,
      inspected: inspectedLanguages,
      uninspected: uninspectedLanguages,
    },
    files: {
      total: totalFiles,
      inspected: inspectedFiles,
      uninspected: uninspectedFiles,
      unknownReportedFiles,
      coverageRatio: totalFiles === 0
        ? 1
        : Number((inspectedFiles.length / totalFiles).toFixed(4)),
    },
    categories: {
      expected: expectedCategories,
      covered: coveredCategories,
      missing: missingCategories,
    },
    roles,
    ...(gapFill ? { gapFill } : {}),
  };
}

function recommendGapFill(input: {
  profile: ProjectProfile;
  selectedRoleIds: readonly MoaRoleId[];
  executionByRole: ReadonlyMap<MoaRoleId, MoaRoleExecutionCoverage>;
  uninspectedFiles: readonly string[];
  missingCategories: readonly MoaCoverageCategory[];
  maxFiles: number;
  maxCategories: number;
}): MoaGapFillRecommendation | undefined {
  if (
    input.selectedRoleIds.length === 0
    || (input.uninspectedFiles.length === 0 && input.missingCategories.length === 0)
  ) {
    return undefined;
  }
  const ranked = input.selectedRoleIds
    .map((roleId) => {
      const role = moaRoleById(roleId);
      const execution = input.executionByRole.get(roleId);
      const missingForRole = role.categories.filter((category) =>
        input.missingCategories.includes(category)
      );
      const failureWeight = !execution || execution.status === "failed"
        ? 100
        : execution.status === "skipped"
          ? 80
          : execution.status === "partial"
            ? 40
            : 0;
      const relevantFiles = input.uninspectedFiles.filter((file) => {
        const lower = file.toLowerCase();
        return role.pathHints.some((hint) => lower.includes(hint));
      });
      return {
        role,
        score: failureWeight + (missingForRole.length * 10) + Math.min(5, relevantFiles.length),
        missingForRole,
        relevantFiles,
      };
    })
    .sort((left, right) =>
      right.score - left.score || left.role.order - right.role.order
    );
  const selected = ranked[0];
  if (!selected) {
    return undefined;
  }
  const remainingFiles = input.uninspectedFiles.filter((file) =>
    !selected.relevantFiles.includes(file)
  );
  const files = [...selected.relevantFiles, ...remainingFiles]
    .slice(0, input.maxFiles);
  const categories = (
    selected.missingForRole.length > 0
      ? selected.missingForRole
      : selected.role.categories
  )
    .slice()
    .sort()
    .slice(0, input.maxCategories);
  if (files.length === 0 && categories.length === 0) {
    return undefined;
  }
  return {
    bounded: true,
    maxAdditionalRounds: 1,
    roleId: selected.role.id,
    files,
    categories,
    reason: gapFillReason(selected.role.id, files.length, categories.length),
  };
}

function canonicalRoleIds(roleIds: readonly MoaRoleId[]): MoaRoleId[] {
  const selected = new Set(roleIds);
  return MOA_ROLES
    .filter((role) => selected.has(role.id))
    .map((role) => role.id);
}

function canonicalExecutions(
  executions: readonly MoaRoleExecutionCoverage[],
): MoaRoleExecutionCoverage[] {
  const byRole = new Map<MoaRoleId, MoaRoleExecutionCoverage[]>();
  for (const execution of executions) {
    const records = byRole.get(execution.roleId) ?? [];
    records.push(execution);
    byRole.set(execution.roleId, records);
  }
  return MOA_ROLES.flatMap((role) => {
    const records = byRole.get(role.id);
    if (!records || records.length === 0) {
      return [];
    }
    const claimRecords = records.filter((record) =>
      record.status === "completed" || record.status === "partial"
    );
    return [{
      roleId: role.id,
      status: combinedExecutionStatus(records.map((record) => record.status)),
      inspectedFiles: [...new Set(
        claimRecords.flatMap((record) => [...record.inspectedFiles]),
      )].sort(),
      coveredCategories: [...new Set(
        claimRecords.flatMap((record) => [...record.coveredCategories]),
      )].sort(),
    }];
  });
}

function rolesWithStatus(
  selectedRoleIds: readonly MoaRoleId[],
  executions: ReadonlyMap<MoaRoleId, MoaRoleExecutionCoverage>,
  status: MoaRoleExecutionStatus,
): MoaRoleId[] {
  return selectedRoleIds.filter((roleId) => executions.get(roleId)?.status === status);
}

function combinedExecutionStatus(
  statuses: readonly MoaRoleExecutionStatus[],
): MoaRoleExecutionStatus {
  const unique = new Set(statuses);
  if (unique.size === 1) {
    return statuses[0]!;
  }
  if (unique.has("failed")) {
    return "failed";
  }
  return "partial";
}

function gapFillReason(
  roleId: MoaRoleId,
  fileCount: number,
  categoryCount: number,
): string {
  return `${roleId} has the highest deterministic coverage gap; inspect ${fileCount} file${fileCount === 1 ? "" : "s"} across ${categoryCount} categor${categoryCount === 1 ? "y" : "ies"} in one additional bounded round.`;
}

function boundedInt(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}
