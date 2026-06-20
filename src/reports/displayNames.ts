const scannerDisplayNames = new Map<string, string>([
  ["hermsec-offline", "HermSec heuristics"],
  ["hermsec-heuristics", "HermSec heuristics"],
  ["hermsec", "HermSec"],
  ["semgrep", "Semgrep"],
  ["gitleaks", "Gitleaks"],
  ["trufflehog", "TruffleHog"],
  ["osv-scanner", "OSV-Scanner"],
  ["trivy", "Trivy"],
  ["checkov", "Checkov"],
  ["bandit", "Bandit"],
  ["pip-audit", "pip-audit"],
  ["pmg", "SafeDep PMG npm audit"],
  ["npm-audit", "SafeDep PMG npm audit"],
  ["retire", "Retire.js"],
  ["spotbugs", "FindSecBugs / SpotBugs"],
  ["dependency-check", "OWASP Dependency-Check"],
  ["psalm", "Psalm taint analysis"],
  ["composer", "Composer audit"],
  ["gosec", "gosec"],
  ["govulncheck", "govulncheck"],
  ["cargo", "cargo-audit"],
  ["brakeman", "Brakeman"],
  ["flawfinder", "Flawfinder"],
  ["cppcheck", "Cppcheck"],
  ["dotnet", ".NET vulnerable packages"],
]);

export function displayScannerName(value: string | undefined): string {
  const key = value?.trim();
  if (!key) return "Scanner";
  return scannerDisplayNames.get(key.toLowerCase()) ?? key;
}
