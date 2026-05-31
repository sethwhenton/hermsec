export const hermsecSkillRules = {
  scanRequest: "scan.plan then scan.run",
  findingExplanation: "scan.getFindings then model explanation",
  providerSetup: "provider.healthCheck then provider.setPreference",
  securityNews: "intel.update from trusted feeds only",
  scheduleRequest: "schedule.create with git-aware scan policy",
  unsafeRequest: "refusal plus safe defensive alternative"
} as const;
