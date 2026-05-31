[CmdletBinding()]
param(
  [switch]$AllowMissingPmg
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

$env:PATH = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
$env:PMG_DISABLE_TELEMETRY = "true"

$requiredTools = @("semgrep", "gitleaks", "bandit", "osv-scanner", "pip-audit", "pmg")
$missingTools = @()

foreach ($tool in $requiredTools) {
  $command = Get-Command $tool -ErrorAction SilentlyContinue
  if ($null -eq $command) {
    $missingTools += $tool
    Write-Host "MISSING $tool"
  } else {
    Write-Host "FOUND   $tool -> $($command.Source)"
  }
}

if ($missingTools.Count -gt 0) {
  $onlyPmgMissing = $missingTools.Count -eq 1 -and $missingTools[0] -eq "pmg"
  if (-not ($AllowMissingPmg -and $onlyPmgMissing)) {
    throw "Missing production scanner tool(s): $($missingTools -join ', '). See docs/pmg-setup.md for PMG setup."
  }
}

if (Get-Command pmg -ErrorAction SilentlyContinue) {
  pmg npm test
} else {
  npm test
}

$doctorJson = node dist/src/bin/hermsec.js doctor --json | Out-String
$doctor = $doctorJson | ConvertFrom-Json
if (-not $doctor.ok) {
  Write-Host $doctorJson
  throw "Hermsec doctor failed."
}

$pmgCheck = $doctor.data.checks | Where-Object { $_.id -eq "command-pmg" } | Select-Object -First 1
if ($null -eq $pmgCheck) {
  throw "Hermsec doctor did not report command-pmg."
}
if ($pmgCheck.status -ne "pass" -and -not $AllowMissingPmg) {
  Write-Host $doctorJson
  throw "PMG is not production-ready: doctor reported command-pmg=$($pmgCheck.status)."
}

node dist/src/bin/hermsec.js eval run --mode scanner-only --out .hermsec\verify-eval

Write-Host "Hermsec production verification completed."
