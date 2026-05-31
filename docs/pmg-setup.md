# SafeDep PMG Setup

Hermsec can run npm dependency evidence through SafeDep PMG when `pmg` is available on `PATH`. PMG is intentionally a machine-level prerequisite, not a vendored project dependency.

Official PMG setup references:

- SafeDep PMG quickstart: <https://docs.safedep.io/pmg/quickstart>
- SafeDep PMG GitHub repository: <https://github.com/safedep/pmg>

## Install Options

Use one official install path after explicit machine-level approval:

```powershell
# Option 1: if Go is installed
go install github.com/safedep/pmg@latest
```

Or download the latest Windows binary from the PMG GitHub releases page and add its directory to the user or machine `PATH`.

Hermsec does not require PMG shell aliases. The scanner harness invokes PMG directly as:

```powershell
$env:PMG_DISABLE_TELEMETRY = "true"
pmg npm audit --json --package-lock-only --ignore-scripts=true
```

Do not run `pmg setup install` unless you explicitly want PMG to add shell aliases for package-manager commands on this machine.

## Verify

Restart the terminal or refresh `PATH`, then run:

```powershell
$env:PATH = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
Get-Command pmg
$env:PMG_DISABLE_TELEMETRY = "true"
pmg version
node dist/src/bin/hermsec.js doctor --json
.\scripts\verify-production.ps1
```

Production verification is not complete until `doctor` reports `command-pmg` as `pass` and `scripts/verify-production.ps1` exits successfully without `-AllowMissingPmg`.
