# Hermsec Manual Mode: Start-to-Finish Research And Build Plan

Date: 2026-05-31

## Executive Decision

Hermsec should be built as a local-first security review tool with a CLI scan engine first and a TUI wrapper second.

The scanner engine should work like this:

```text
hermsec scan <github-url-or-local-path> --md report.md --json report.json
```

The TUI should sit on top of the same engine:

```text
hermsec
> scan https://github.com/org/repo
```

This gives us a good presentation because the TUI is visual, but it also gives us a real engineering story because the core scanner can run in scripts, CI, and future Hermes background mode.

The model should not be the source of truth. The source of truth is scanner output and vulnerability databases. The model explains, deduplicates, prioritizes, and writes developer-friendly fix guidance.

## What We Are Building

Hermsec manual mode is a defensive repository security assistant.

It accepts:

- a public GitHub URL
- a private GitHub URL if the user already has access
- a local repository path

It produces:

- a terminal/TUI report
- a Markdown report
- a normalized JSON report
- optional scan history for future comparison

The MVP should support:

- Python source scanning
- JavaScript/TypeScript source scanning
- npm dependency vulnerability checks
- Python dependency vulnerability checks
- secret scanning
- AI explanation through a bring-your-own-model provider
- optional scheduled scans
- optional report delivery through email or Telegram
- online/offline scan modes

The project should not:

- attack live systems
- generate exploit code
- claim CVEs without database evidence
- install dependencies by default
- send private source code to a cloud model without consent

## End-to-End Manual Mode Flow

```text
User input
  |
  |-- local path --------------------------+
  |                                        |
  |-- GitHub URL                           |
       |                                   |
       |-- public repo: clone read-only    |
       |-- private repo: require auth      |
                                           |
                                           v
Temporary scan workspace or local repo
  |
  v
Repository discovery
  |
  |-- languages
  |-- lockfiles
  |-- dependency manifests
  |-- git metadata
  |-- ignored folders
  |
  v
Scanner plan
  |
  |-- Bandit for Python source
  |-- Semgrep for code patterns
  |-- Gitleaks for secrets
  |-- npm audit / OSV-Scanner for npm
  |-- pip-audit / OSV-Scanner for Python
  |
  v
Raw scanner outputs
  |
  v
Normalized finding schema
  |
  v
Enrichment
  |
  |-- OSV.dev details
  |-- GitHub Advisory details
  |-- NVD CVSS/CWE details
  |-- CISA KEV exploited-in-the-wild flag
  |
  v
Model review
  |
  |-- explain evidence
  |-- deduplicate similar findings
  |-- suggest fixes
  |-- generate summary
  |
  v
Reports
  |
  |-- terminal/TUI
  |-- Markdown
  |-- JSON
  |-- optional history DB
```

## Online, Offline, And Scheduled Operation

Manual mode is the first user flow, but the product should also support scheduled scans. See:

```text
docs/research/automation-online-offline-notifications.md
```

Important definitions:

- Offline mode: local scanners and cached data only; queue reports/enrichment for later.
- Online mode: local scanners plus fresh advisory lookups, supply-chain research, model explanations, and notifications.
- Scheduled mode: user chooses a scan time, such as every weekday at 18:00.
- Sync mode: enrich queued offline scans when internet access returns.

This extends the manual scanner into a practical assistant for users who let coding agents modify files during the day.

## Repository Input And Access Strategy

### Local Path

Local scanning should be the safest and most reliable path.

The user runs:

```bash
hermsec scan ./my-repo
hermsec scan C:\Users\name\project
```

Hermsec should:

- resolve the absolute path
- confirm the folder exists
- detect whether it is a Git repository
- scan the working tree
- avoid modifying files
- skip heavy/generated folders by default

Suggested default skip list:

```text
.git
node_modules
vendor
venv
.venv
dist
build
coverage
.next
.nuxt
.cache
```

### Public GitHub URL

The user runs:

```bash
hermsec scan https://github.com/owner/repo
```

Hermsec should:

- parse `owner/repo`
- use a temporary workspace
- clone read-only with `git clone --depth 1` when possible
- clean up the temporary clone unless `--keep-workspace` is set
- record the commit SHA in the report

GitHub's cloning docs confirm that cloning creates a local copy, and GitHub CLI also supports `gh repo clone <repository>`.

### Private GitHub URL

Private repository access should be handled through the user's existing GitHub setup, not by storing secrets in Hermsec.

Supported options:

1. User scans a local clone. This is the best privacy path.
2. User has GitHub CLI authenticated. Hermsec can call `gh auth status` and then `gh repo clone`.
3. User has SSH auth configured. Hermsec can let `git clone git@github.com:owner/repo.git` use the local SSH agent.
4. User provides a token through an environment variable such as `GITHUB_TOKEN`.

Hermsec should not ask the user to paste a GitHub token into a normal prompt. If a token path is needed later, use environment variables or OS credential storage.

Private access behavior:

- If unauthenticated clone fails, say "authentication required or repository not found" rather than claiming the repository does not exist.
- If `gh` exists, use `gh auth status` to explain the next action.
- If a token is present, use least privilege. A fine-grained token should only need read access to repository contents for cloning/API reads.

## Package Manager Safety

Hermsec should be a scanner, not an installer.

Default rule:

- Do not run `npm install`, `npm ci`, `pnpm install`, `yarn install`, `npx`, `pnpm dlx`, `bunx`, or package lifecycle scripts during a scan.

Why:

- install scripts can execute arbitrary code
- modern supply-chain incidents often happen at install time
- lockfile scans are enough for the MVP

Allowed by default:

- parse lockfiles
- run scanner CLIs that do not install project dependencies
- run `npm audit --json --package-lock-only` when a package lock exists
- run `osv-scanner scan --format json` over lockfiles or the project directory
- run `pip-audit -r requirements.txt -f json` for requirements files

If a project has only `package.json` and no lockfile:

- report "dependency versions are not locked"
- run OSV queries only for exact pinned versions if available
- mark findings lower confidence
- ask for explicit permission before generating a lockfile

If future dependency resolution is allowed:

- require explicit user approval
- use `--ignore-scripts`
- prefer lockfile-respecting commands
- route through SafeDep PMG if available
- never run package lifecycle scripts silently

## Vulnerability Intelligence Sources

Hermsec needs two kinds of sources:

1. package-version vulnerability sources
2. current-priority/security-topic sources

### npm Audit

Use for npm projects with `package-lock.json` or `npm-shrinkwrap.json`.

Command:

```bash
npm audit --json --package-lock-only
```

What it gives:

- npm registry advisory results
- severity
- package names
- vulnerable version ranges
- remediation guidance

Important details:

- npm audit sends dependency information to the configured npm registry.
- npm normally requires a lockfile for reliable audit results.
- npm audit has JSON output.

Use in Hermsec:

- primary npm SCA source for package-lock projects
- normalize to dependency findings
- do not run `npm audit fix` in MVP

### OSV.dev And OSV-Scanner

Use for multi-ecosystem package vulnerability scanning.

OSV.dev is useful because it aggregates ecosystem advisory data in a version-aware schema. It supports ecosystems such as npm and PyPI, and OSV's data sources include GitHub Advisory Database, PyPI Advisory Database, Go Vulnerability Database, RustSec, and others.

Commands:

```bash
osv-scanner scan --format json <project-dir>
osv-scanner scan --format json -L package-lock.json
```

API:

```text
POST https://api.osv.dev/v1/query
POST https://api.osv.dev/v1/querybatch
```

Use in Hermsec:

- primary cross-ecosystem dependency scanner
- useful for npm, PyPI, Go, Rust, Maven, NuGet, RubyGems, and more
- good second source beside native package manager audit
- useful for enrichment because OSV records include aliases such as CVE and GHSA IDs

### GitHub Advisory Database

Use for advisory enrichment and presentation.

GitHub Advisory Database includes:

- GitHub-reviewed advisories
- unreviewed advisories
- malware advisories

The malware advisories are especially relevant to npm. GitHub says malware advisories are exclusive to the npm ecosystem and come from npm security team data.

Use in Hermsec:

- enrich CVE/GHSA details
- verify package ecosystem and patched version data
- mention malware advisory status where available
- optional GraphQL query for details when GitHub auth exists

### NVD CVE API

Use for CVE metadata enrichment.

NVD is useful for:

- CVSS data
- CWE data
- CPE/applicability data
- official CVE descriptions and references

Use in Hermsec:

- enrich already-known CVEs from npm/OSV/GHSA
- do not use NVD alone to decide whether an npm/PyPI package version is affected; ecosystem-specific sources are usually better for package version ranges
- cache results because NVD APIs are paginated and rate limited

### CISA KEV Catalog

Use for prioritization.

CISA KEV is a catalog of vulnerabilities known to be exploited in the wild. It is available as JSON and CSV.

Use in Hermsec:

- if a dependency finding has a CVE listed in KEV, raise priority
- label as "known exploited in the wild"
- highlight in executive summary
- use as a "current security topic" source for presentation

### OpenSSF Scorecard

Use as a future supply-chain risk layer, not MVP core.

Scorecard evaluates open source project security posture with checks such as maintenance, branch protection, pinned dependencies, SAST, token permissions, and vulnerabilities.

Use in Hermsec later:

- risk score for direct dependencies
- maintainer/project hygiene warnings
- useful for "package trust" beyond known CVEs

### npm Provenance And Trusted Publishing

Use as a future package-trust feature.

npm provenance can help users verify where and how a package was published. npm trusted publishing uses OIDC and can automatically generate provenance attestations for packages.

Use in Hermsec later:

- show whether a direct npm dependency version has provenance
- flag missing provenance as informational, not vulnerability
- explain supply-chain trust context

## Scanner Stack

### Bandit

Purpose:

- Python SAST

Use for:

- hardcoded passwords
- `eval`
- unsafe subprocess usage
- weak crypto
- insecure temp files
- common Python security mistakes

Command:

```bash
bandit -r <repo> -f json -o bandit.json
```

Output:

- JSON
- severity
- confidence
- file path
- line number
- test ID
- CWE/more-info fields depending on rule/version

MVP role:

- required for Python demo

### Semgrep

Purpose:

- general SAST and custom pattern matching

Use for:

- JavaScript/TypeScript risky code
- Python risky code
- framework-specific rules
- custom demo rules

Commands:

```bash
semgrep scan --config auto --json --output semgrep.json <repo>
semgrep scan --config rules/semgrep --json --output semgrep.json <repo>
```

Output:

- JSON
- SARIF
- rule ID
- severity
- path
- start/end line
- message
- metadata including CWE/OWASP references when rule provides them

MVP role:

- required for cross-language code patterns
- lets us build one or two custom rules for a reliable demo

### Gitleaks

Purpose:

- secret scanning

Command:

```bash
gitleaks detect --source <repo> --report-format json --report-path gitleaks.json --no-banner
```

Output:

- JSON
- SARIF
- file
- line
- rule ID
- secret fingerprint

MVP role:

- required for hardcoded secret demo
- important because secret leaks are easy for an audience to understand

### pip-audit

Purpose:

- Python dependency vulnerability scanning

Commands:

```bash
pip-audit -r requirements.txt -f json
pip-audit --locked -f json
pip-audit -r requirements.txt -f json --vulnerability-service osv
```

Output:

- JSON
- package name/version
- vulnerability ID
- fix versions
- aliases
- descriptions

MVP role:

- Python dependency layer
- good complement to OSV-Scanner

### OSV-Scanner

Purpose:

- multi-ecosystem dependency scanning

Commands:

```bash
osv-scanner scan --format json <repo>
osv-scanner scan --format json -L package-lock.json
```

Output:

- JSON
- source path and type
- package name/version/ecosystem
- vulnerabilities with aliases

MVP role:

- cross-ecosystem dependency source
- backup for npm/Python native tools

### npm audit

Purpose:

- npm dependency vulnerability scanning

Command:

```bash
npm audit --json --package-lock-only
```

MVP role:

- primary npm-native vulnerability check when `package-lock.json` exists

Do not run:

```bash
npm audit fix
npm install
npm ci
```

unless explicitly approved.

## NPM-Specific Plan

NPM is important because it gives us both CVE-style dependency issues and current supply-chain talking points.

Hermsec should detect:

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`

MVP priority:

1. `package-lock.json` with `npm audit`
2. `package-lock.json` with OSV-Scanner
3. `pnpm-lock.yaml` / `yarn.lock` with OSV-Scanner
4. exact package versions in `package.json`, lower confidence

Report language:

- "Known vulnerable dependency" for CVE/GHSA/OSV package findings.
- "Known malicious package advisory" if the source identifies a malware advisory.
- "Dependency risk warning" for no lockfile, unpinned versions, or direct dependency hygiene concerns.

Important limitation:

- npm audit and OSV catch known advisories. They may not catch a brand-new malicious package before it is reported. Hermsec should be honest about that.

Future npm supply-chain features:

- check npm provenance
- check package age/maintainer changes
- check direct dependencies with OpenSSF Scorecard where source repository is known
- flag package install scripts for manual review
- detect suspicious `postinstall`, `preinstall`, or obfuscated dependency scripts without executing them

## When The Model Takes Over

The model should take over only after scanner evidence exists.

Good model inputs:

- normalized finding JSON
- scanner message
- severity/confidence
- exact file path
- small code snippet around the finding
- package name/version and advisory data
- CVE/GHSA/OSV links already found by tools

Bad model inputs:

- entire private repo by default
- raw secrets
- huge files
- unsupported claims like "find every vulnerability"
- exploit-generation prompts

Model tasks:

- deduplicate related findings
- explain impact in plain developer language
- map code pattern findings to CWE/OWASP categories when evidence supports it
- explain why a dependency CVE matters
- suggest safe remediation steps
- write final Markdown sections
- produce a strict JSON explanation object

Model must not:

- invent CVEs
- invent affected versions
- claim exploitability without evidence
- ask to run unapproved installs
- generate exploit instructions

Prompt shape:

```text
You are Hermsec, a defensive code security assistant.
Use only the scanner evidence supplied below.
Do not invent CVEs, package versions, files, line numbers, or exploit details.
If a CVE/GHSA/OSV ID is not present in evidence, use CWE/category language instead.
Return concise developer guidance with: impact, why it was flagged, suggested fix, confidence, and evidence references.

Finding JSON:
{finding_json}

Code snippet, if user allowed code context:
{snippet}
```

Use structured model output where possible:

```ts
type ModelExplanation = {
  title: string;
  impact: string;
  evidenceSummary: string;
  suggestedFix: string;
  confidenceReason: string;
  safeNextSteps: string[];
  cveUsage: "from_evidence" | "not_applicable" | "not_present";
};
```

## Normalized Data Model

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";
type Confidence = "confirmed" | "high" | "medium" | "low";

type Finding = {
  id: string;
  sourceTool: "bandit" | "semgrep" | "gitleaks" | "pip-audit" | "npm-audit" | "osv-scanner" | "model";
  category: "code" | "dependency" | "secret" | "supply-chain" | "config";
  title: string;
  severity: Severity;
  confidence: Confidence;
  file?: string;
  startLine?: number;
  endLine?: number;
  packageName?: string;
  installedVersion?: string;
  fixedVersions?: string[];
  ecosystem?: "npm" | "PyPI" | "Go" | "Maven" | "RubyGems" | "NuGet" | "Rust" | string;
  identifiers: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
    cwe?: string[];
  };
  evidence: {
    message: string;
    rawSourceId?: string;
    references?: string[];
    snippetAllowed?: boolean;
    snippet?: string;
  };
  enrichment?: {
    nvdCvss?: number;
    kevKnownExploited?: boolean;
    firstPatchedVersion?: string;
    advisoryPublishedAt?: string;
  };
  modelExplanation?: ModelExplanation;
};

type ScanReport = {
  scanId: string;
  scannedAt: string;
  target: {
    input: string;
    kind: "local" | "github";
    resolvedPath?: string;
    remoteUrl?: string;
    commitSha?: string;
    privateAccessMode?: "local" | "gh-cli" | "ssh" | "token" | "none";
  };
  tools: {
    name: string;
    version?: string;
    status: "ran" | "skipped" | "failed";
    reason?: string;
  }[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    confirmedCves: number;
    knownExploited: number;
  };
  findings: Finding[];
};
```

## Confidence Rules

Use these labels consistently:

- `confirmed`: package version matches advisory evidence, or a secret scanner found a high-confidence secret pattern.
- `high`: two tools report the same issue or one tool provides exact file/line/code evidence with a strong rule.
- `medium`: one scanner reports a plausible issue with exact location.
- `low`: model-only concern or weak heuristic. Low findings should be suggestions, not confirmed vulnerabilities.

Special handling:

- CVE findings should almost always be `confirmed` only when from dependency/advisory data.
- Code findings should normally be CWE/category findings, not CVE findings.
- CISA KEV raises priority but does not change whether the package version is affected.

## Report Format

Markdown report:

```markdown
# Hermsec Security Report

## Scan Metadata

- Target:
- Commit:
- Scan date:
- Access mode:
- Model provider:
- Tools used:

## Executive Summary

- Total findings:
- Critical:
- High:
- Known exploited CVEs:
- Secrets:

## Priority Actions

1. Rotate leaked secrets.
2. Patch dependencies with known exploited CVEs.
3. Fix high-confidence code vulnerabilities.

## Findings

### HERM-001: Vulnerable npm package

- Severity:
- Confidence:
- Package:
- Installed version:
- Fixed version:
- IDs:
- Source tools:

#### Explanation

#### Suggested Fix

#### Evidence

## Limitations

- Static analysis can have false positives.
- Unknown/zero-day vulnerabilities may not be detected.
- No dependency install was performed.
```

Terminal/TUI report:

- summary counts
- top 5 priority findings
- model/provider used
- path to Markdown and JSON reports
- warning if cloud model received snippets

JSON report:

- exact `ScanReport` object for testability and future CI

## TUI Design

The TUI should be a friendly wrapper, not the only interface.

MVP TUI screens:

1. Welcome and model/provider status
2. Target input
3. Access/auth check
4. Scan plan confirmation
5. Progress screen
6. Findings summary
7. Finding detail view
8. Export complete screen

Example:

```text
HERMSEC
Repository Security Review

Target:
> https://github.com/owner/repo

Access:
[ok] public repository cloned

Plan:
[x] Semgrep
[x] Gitleaks
[x] npm audit
[x] OSV-Scanner
[ ] Bandit skipped, no Python files

Model:
OpenRouter / local Ollama / no model
```

For implementation, start simple:

- `commander` for CLI commands
- `@inquirer/prompts` for interactive prompts
- `ora` or simple text progress for status
- `cli-table3` or custom formatting for summaries

If we need a richer full-screen TUI later:

- use Ink, which lets us build React-style terminal UIs

## Suggested Code Architecture

```text
Hermsec Proj/
  package.json
  src/
    index.ts
    cli/
      commands.ts
      interactive.ts
    repo/
      parseTarget.ts
      prepareWorkspace.ts
      gitAuth.ts
      discover.ts
    scanners/
      bandit.ts
      semgrep.ts
      gitleaks.ts
      npmAudit.ts
      pipAudit.ts
      osvScanner.ts
    normalize/
      finding.ts
      dedupe.ts
      severity.ts
    enrich/
      osv.ts
      githubAdvisory.ts
      nvd.ts
      cisaKev.ts
      cache.ts
    model/
      provider.ts
      openRouter.ts
      ollama.ts
      lmStudio.ts
      noModel.ts
      prompts.ts
    report/
      markdown.ts
      terminal.ts
      json.ts
    history/
      store.ts
    util/
      exec.ts
      paths.ts
      redaction.ts
  rules/
    semgrep/
      python-security.yml
      node-security.yml
  examples/
    vulnerable-python-app/
    vulnerable-node-app/
  reports/
```

## Implementation Phases

### Phase 0: Presentation Research Pack

Deliverables:

- this research file
- architecture diagram
- demo script outline
- source list

Status:

- in progress

### Phase 1: Core CLI Skeleton

Deliverables:

- `hermsec scan <target>`
- target parser
- local path scanning stub
- GitHub clone into temp workspace
- JSON report with metadata and no findings

Acceptance:

- scans a local folder without modifying it
- clones a public GitHub repo to temp folder
- records commit SHA

### Phase 2: Discovery And Scanner Plan

Deliverables:

- language detection
- lockfile/manifest detection
- skip-list handling
- scanner plan output

Acceptance:

- Node repo triggers npm/OSV/Semgrep/Gitleaks plan
- Python repo triggers Bandit/pip-audit/OSV/Semgrep/Gitleaks plan
- generated folders are skipped

### Phase 3: Scanner Wrappers

Deliverables:

- run Bandit and parse JSON
- run Semgrep and parse JSON
- run Gitleaks and parse JSON
- run npm audit and parse JSON
- run pip-audit and parse JSON
- run OSV-Scanner and parse JSON

Acceptance:

- each scanner has a fixture test
- missing tool is reported as skipped with install hint
- scanner failure does not crash whole scan

### Phase 4: Normalization And Dedupe

Deliverables:

- common `Finding` schema
- severity mapping
- confidence mapping
- fingerprinting and dedupe

Acceptance:

- same dependency CVE from npm audit and OSV merges into one finding
- same code location from Bandit/Semgrep becomes one higher-confidence finding where reasonable

### Phase 5: Enrichment

Deliverables:

- OSV detail lookup by ID
- CISA KEV local/cache lookup
- optional NVD lookup by CVE
- optional GitHub Advisory lookup

Acceptance:

- known exploited CVE gets `kevKnownExploited: true`
- CVSS/CWE data appears when available
- enrichment cache avoids repeated calls

### Phase 6: Model Explanation

Deliverables:

- provider interface
- OpenRouter provider
- Ollama provider
- LM Studio/OpenAI-compatible provider
- no-model fallback
- structured explanation output

Acceptance:

- scan can run without a model
- cloud model path shows privacy warning
- model sees only findings/snippets, not whole repo by default
- model output cannot add new CVEs unless present in evidence

### Phase 7: Reports

Deliverables:

- Markdown report
- terminal summary
- JSON report
- optional history file

Acceptance:

- report includes metadata, tools, summary, findings, evidence, suggested fixes, limitations
- JSON validates against our schema

### Phase 8: TUI Wrapper

Deliverables:

- interactive target input
- provider selection
- access check display
- progress screen
- finding summary/detail views

Acceptance:

- demo can be run entirely from TUI
- user can export reports
- TUI calls the same engine as CLI

### Phase 9: Demo Repository And Presentation

Deliverables:

- vulnerable Python demo app
- vulnerable Node demo app
- screenshots or terminal recording
- final slide deck

Demo findings:

- SQL injection or command injection code pattern
- hardcoded secret
- old vulnerable dependency
- npm no-lockfile warning or package advisory

### Phase 10: Automation And Notifications

Deliverables:

- schedule registry
- in-app scheduled scan
- offline queue
- online sync command
- notification preference setup
- optional Telegram test message
- optional AgentMail test email

Acceptance:

- user can schedule a scan time
- offline scans save local reports and queued enrichment
- online sync enriches queued results
- notification failures do not lose reports
- secrets are redacted before reports leave the machine

## Demo Strategy

Use two demo targets:

1. `examples/vulnerable-python-app`
2. `examples/vulnerable-node-app`

Python demo contents:

- Flask route with SQL string concatenation
- `subprocess(..., shell=True)` with user input
- hardcoded fake API key
- `requirements.txt` with intentionally old vulnerable package

Node demo contents:

- Express route with unsafe command execution or unsafe redirect
- hardcoded fake token
- `package-lock.json` with known vulnerable dependency

Important:

- Use fake secrets only.
- Use intentionally vulnerable toy code.
- Do not include exploit instructions.
- Keep the demo small so scans finish quickly.

Presentation story:

1. Developers ship fast and miss security checks.
2. Existing scanners produce scattered raw output.
3. Hermsec combines scanners, advisory databases, and AI explanation.
4. The model is grounded in evidence, so it does not invent CVEs.
5. Manual mode works today; Hermes scheduled mode is the future.

## Evaluation Plan

Technical checks:

- CLI scans local path
- CLI scans public GitHub URL
- private repo failure is explained safely
- each scanner wrapper handles missing tools
- Markdown/JSON reports generated
- findings contain evidence references
- no installs are run during scan

Security correctness checks:

- dependency CVE only appears when scanner/advisory data contains it
- code findings use CWE/category language
- secrets are redacted in model prompts and reports
- cloud model prompts exclude full private source by default

Presentation checks:

- demo completes in under 5 minutes
- output has at least one code finding
- output has at least one dependency finding
- output has at least one secret finding
- final report is readable by a non-security developer

## Known Risks And Mitigations

| Risk | Mitigation |
|---|---|
| Tool installation friction | Start with wrappers that show clear missing-tool messages; provide setup docs. |
| npm audit needs lockfile | Prefer lockfile scan; report no-lockfile as dependency confidence limitation. |
| Private repo access confusion | Prefer local clone; use `gh auth status`; never claim private repo does not exist without auth. |
| Model hallucination | Evidence-only prompts; structured output; CVE guardrail in code. |
| False positives | Confidence labels; source tool evidence; report limitations. |
| Large repos are slow | Skip generated folders; add file limits; show scanner plan before running. |
| Cloud privacy | Local model option; ask before sending snippets; redact secrets. |
| Brand-new malicious package not in databases | Say known-advisory scanners cannot guarantee detection of unreported malware; future script/provenance heuristics. |

## Best Sources To Cite In Presentation

- npm audit docs: https://docs.npmjs.com/cli/audit/
- OSV.dev API docs: https://google.github.io/osv.dev/api/
- OSV-Scanner output docs: https://google.github.io/osv-scanner/output/
- OSV data sources: https://google.github.io/osv.dev/data/
- GitHub Advisory Database docs: https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/about-the-github-advisory-database
- GitHub Advisory Database browse page: https://github.com/advisories
- NVD CVE API docs: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Bandit docs: https://bandit.readthedocs.io/en/latest/man/bandit.html
- Semgrep local CLI docs: https://semgrep.dev/docs/getting-started/cli
- Semgrep JSON/SARIF docs: https://semgrep.dev/docs/semgrep-appsec-platform/json-and-sarif
- Gitleaks docs: https://github.com/gitleaks/gitleaks
- pip-audit docs: https://pypi.org/project/pip-audit/
- GitHub cloning docs: https://docs.github.com/articles/cloning-a-repository
- GitHub CLI `gh repo clone`: https://cli.github.com/manual/gh_repo_clone
- GitHub fine-grained token permissions: https://docs.github.com/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens
- OpenRouter API docs: https://openrouter.ai/docs/api-reference/overview
- Ollama OpenAI compatibility: https://docs.ollama.com/openai
- LM Studio local API server: https://lmstudio.ai/docs/developer/core/server
- OpenSSF Scorecard: https://openssf.org/scorecard/
- npm package provenance: https://docs.npmjs.com/viewing-package-provenance
- npm trusted publishing: https://docs.npmjs.com/trusted-publishers

## Final Recommended MVP

Build this exact version first:

```text
Hermsec Manual Mode MVP

Input:
  local path or public GitHub URL

Languages:
  Python and Node/JavaScript

Scanners:
  Bandit
  Semgrep
  Gitleaks
  pip-audit
  npm audit
  OSV-Scanner

Sources:
  npm registry audit endpoint via npm audit
  OSV.dev via OSV-Scanner/API
  GitHub Advisory Database for explanation/enrichment
  CISA KEV for prioritization
  NVD for CVSS/CWE enrichment

AI:
  BYOM provider
  OpenRouter first
  Ollama/LM Studio local option
  no-model fallback

Outputs:
  terminal/TUI summary
  Markdown report
  JSON report
```

This is realistic, defensible, useful, and presentable.
