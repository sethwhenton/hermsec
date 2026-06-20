import type { ScannerSettings } from "../renderer/src/types/scanners";

const DEFAULT_SCANNERS = [
  ["hermsec-heuristics", true, false],
  ["semgrep", true, true],
  ["gitleaks", true, true],
  ["trufflehog", false, false],
  ["osv-scanner", true, true],
  ["trivy", true, true],
  ["checkov", true, true],
  ["bandit", true, true],
  ["pip-audit", true, true],
  ["pmg", true, true],
  ["retire", true, false],
  ["findsecbugs", true, false],
  ["dependency-check", true, false],
  ["psalm", true, false],
  ["composer-audit", true, false],
  ["gosec", true, false],
  ["govulncheck", true, false],
  ["cargo-audit", true, false],
  ["brakeman", true, false],
  ["flawfinder", true, false],
  ["cppcheck", true, false],
  ["dotnet-vulnerable", true, false],
] as const;

export function defaultScannerSettings(): ScannerSettings {
  return {
    autoInstallMissing: true,
    allowOnlineUpdates: true,
    labInstallAll: false,
    items: DEFAULT_SCANNERS.map(([id, enabled, autoInstall]) => ({ id, enabled, autoInstall })),
  };
}

export function normalizeScannerSettings(settings?: Partial<ScannerSettings>): ScannerSettings {
  const defaults = defaultScannerSettings();
  const byId = new Map((settings?.items ?? []).map((entry) => [entry.id, entry]));
  return {
    autoInstallMissing: Boolean(settings?.autoInstallMissing ?? defaults.autoInstallMissing),
    allowOnlineUpdates: Boolean(settings?.allowOnlineUpdates ?? defaults.allowOnlineUpdates),
    labInstallAll: Boolean(settings?.labInstallAll ?? defaults.labInstallAll),
    items: defaults.items.map((scanner) => {
      const current = byId.get(scanner.id);
      return {
        id: scanner.id,
        enabled: current?.enabled ?? scanner.enabled,
        autoInstall: current?.autoInstall ?? scanner.autoInstall,
      };
    }),
  };
}
