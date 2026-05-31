# HermesSec Project Context

## Project Name

**HermesSec TUI: A CVE Aware AI Security Agent For Repositories**

## Short Description

HermesSec TUI is a terminal based security assistant for developers. A user provides a GitHub repository URL or a local repository path. The tool scans the codebase, checks dependencies against known vulnerability databases, and uses a user selected AI model to explain the findings in simple developer friendly language.

The project is not focused on training a large model from scratch. Instead, it uses a bring your own model approach. The security evidence comes from trusted scanners and vulnerability databases, while the AI model helps summarize, explain, prioritize, and suggest fixes.

## Project Motivation

Modern developers often push code quickly and may miss security problems during development. Many tools already detect vulnerabilities, but their output can be too technical or spread across different scanners. HermesSec combines these outputs into one report and explains them clearly.

The project is related to current trends in:

- AI assisted software development
- DevSecOps
- Software supply chain security
- CVE based dependency checking
- Secure coding support inside developer workflows
- Agentic tools that can run scanners and explain results

## Core Idea

A developer runs HermesSec on a repository.

The agent:

1. Reads the repository structure.
2. Detects programming language and dependency files.
3. Runs source code scanners.
4. Runs dependency vulnerability scanners.
5. Looks up CVE or advisory information.
6. Sends scanner evidence to a selected AI model.
7. Generates a final report with risks and fixes.

The report should include:

- Issue title
- Affected file or package
- Severity
- Related CVE or CWE
- Explanation
- Suggested fix
- Confidence level
- Source tool that found the issue

## Main User Flow

```text
User starts HermesSec TUI
        |
        v
User enters GitHub URL or local repo path
        |
        v
HermesSec clones or opens the repository
        |
        v
HermesSec runs code and dependency scans
        |
        v
HermesSec enriches results with CVE or CWE context
        |
        v
Selected AI model explains findings
        |
        v
HermesSec creates terminal and Markdown reports
```

## Visual Demo Flow

```text
GitHub URL or Local Repo
          |
          v
HermesSec TUI Agent
          |
          +--> Code Scan
          |    Bandit / Semgrep
          |
          +--> Dependency CVE Scan
          |    pip-audit / OSV-Scanner
          |
          +--> AI Explanation
          |    BYOM model
          |
          v
Security Report
Issue | File | Severity | CVE/CWE | Suggested Fix
```

## Scope For Lab 5 MVP

The first version should be small and demo friendly.

### Must Have

- Terminal user interface
- Accept a GitHub URL or local repository path
- Clone GitHub repositories into a temporary workspace
- Scan Python code with Bandit
- Scan code patterns with Semgrep
- Scan Python dependencies with pip-audit or OSV-Scanner
- Generate a terminal report
- Generate a Markdown report
- Allow the user to select or configure an AI model provider
- Explain findings in simple language

### Nice To Have

- NVD CVE API lookup
- OSV.dev API lookup
- GitHub Advisory Database lookup
- JSON report output
- Severity filtering
- Save scan history
- Compare two scans
- Git pre-push hook mode
- GitHub Action mode

### Out Of Scope For MVP

- Training a custom model from scratch
- Fully automatic exploit generation
- Attacking live systems
- Network penetration testing
- Replacing professional security review
- Guaranteeing that all vulnerabilities are found

## Recommended Direction

Build the regular TUI first.

The TUI version is better for the class project because it is easier to demo. The user can enter a GitHub URL, the tool scans the repository, and the results appear in the terminal. This is more visible than a cron based agent that runs silently in the background.

The background Hermes or cron version can be presented as a future extension.

## Possible Future Extension

After the TUI works, the same scanning engine can be reused in:

- Hermes agent background mode
- Cron based scheduled scans
- GitHub Actions
- Git pre-push hooks
- VS Code extension
- CI pipeline security check

## Why Not Train Our Own Model First

Training a useful vulnerability detection model requires large datasets, GPU resources, careful evaluation, and time. For this project, it is more realistic to use existing security tools for detection and use an AI model for explanation and prioritization.

The project still supports custom models through BYOM, which means a user can connect their own model later.

## BYOM Model Strategy

BYOM means bring your own model.

The tool should not be locked to one model provider. Users should be able to choose one of the following:

- OpenRouter
- Ollama
- LM Studio
- OpenAI compatible local server
- Cloud model API
- Future custom model trained by the user

The model should receive structured scanner output, not the entire repository blindly. This reduces cost, improves privacy, and keeps the answer grounded in tool evidence.

## Important Design Principle

The model should not be the only source of truth.

Security scanners and vulnerability databases produce the evidence. The AI model explains the evidence and suggests fixes.

Use this distinction in the report:

- **Confirmed CVE match:** A dependency name and version match a known vulnerability.
- **Possible code vulnerability:** A scanner or rule detected risky code.
- **Similar CVE or CWE pattern:** The code looks related to a known vulnerability class, but it needs human review.

This prevents the tool from making false claims.

## Tools And Technologies

### Programming Languages

- TypeScript for the terminal interface and agent flow
- Python for scanner helper scripts if needed
- Shell commands for running tools

### Agent Or Interface Layer

- OpenRouter Agent TUI or a custom TypeScript TUI
- Optional future Hermes agent integration

### AI Model Providers

- OpenRouter
- Ollama
- LM Studio
- OpenAI compatible APIs
- Any user selected model provider

### Source Code Scanners

- Bandit for Python security scanning
- Semgrep for custom static analysis rules

### Dependency Scanners

- pip-audit for Python dependency vulnerability checks
- OSV-Scanner for open source dependency vulnerability checks

### Vulnerability Databases

- OSV.dev
- NVD CVE API
- GitHub Advisory Database

### Repository Tools

- Git
- GitHub
- GitHub repository URL input
- Local repository path input

### Output Formats

- Terminal output
- Markdown report
- JSON report

### Optional Storage

- JSON file storage for scan history
- SQLite for structured scan history

## Suggested Repository Input

The tool should accept:

```text
https://github.com/user/repo
./local-project
C:\Users\name\project
```

## Suggested CLI Commands

```bash
hermsec scan https://github.com/example/flask-shop
hermsec scan ./my-project
hermsec scan ./my-project --model openrouter
hermsec scan ./my-project --output report.md
hermsec scan ./my-project --json report.json
hermsec configure
```

## Suggested TUI Screens

### Welcome Screen

```text
HERMSEC TUI

model   bring-your-own-model
/help for commands

> scan https://github.com/example/flask-shop
```

### Scan Progress

```text
Repository: github.com/example/flask-shop

[1/5] Reading repository structure
[2/5] Running Bandit
[3/5] Running Semgrep
[4/5] Checking dependencies
[5/5] Generating AI explanation
```

### Final Report Preview

```text
HermesSec Scan Report

Issue: Possible SQL Injection
File: app/routes.py
Severity: High
Related CWE: CWE-89
Reason: User input is directly added to an SQL query.
Suggested Fix: Use parameterized queries.

Issue: Vulnerable dependency
File: requirements.txt
Package: django 2.2.0
Severity: Critical
Related CVE: Confirmed CVE match
Suggested Fix: Upgrade to a patched version.
```

## Expected Report Structure

```markdown
# HermesSec Security Report

## Repository

- Name:
- Source:
- Scan date:
- Model:
- Tools used:

## Summary

- Total findings:
- Critical:
- High:
- Medium:
- Low:

## Findings

### Finding 1

- Type:
- Severity:
- File or package:
- Line:
- CVE or CWE:
- Tool:
- Confidence:

#### Explanation

#### Suggested Fix

#### Evidence
```

## Scanner Responsibilities

### Bandit

Bandit scans Python source code for common security issues.

Examples:

- Hardcoded passwords
- Unsafe subprocess usage
- Use of eval
- Insecure temporary files
- Weak cryptography

### Semgrep

Semgrep scans code using rules. It can detect patterns such as:

- SQL query string concatenation
- Unsafe command execution
- Missing input validation
- Dangerous framework usage

### pip-audit

pip-audit checks Python dependencies against vulnerability databases.

It should be used when the repository has:

- requirements.txt
- pyproject.toml
- setup.py
- setup.cfg

### OSV-Scanner

OSV-Scanner checks open source dependencies against OSV.dev.

It can be useful for multiple ecosystems, depending on lockfiles and manifest files.

## CVE And CWE Strategy

### CVE

CVE means Common Vulnerabilities and Exposures. It is used for known public vulnerabilities.

Use CVE matching mainly for dependencies.

Example:

```text
Package django version 2.2.0 has a known CVE.
```

### CWE

CWE means Common Weakness Enumeration. It describes a class of weakness.

Use CWE for code patterns.

Example:

```text
Possible SQL Injection maps to CWE-89.
```

### Similar CVE Matching

Similar CVE matching should be treated carefully. If the code looks like a known vulnerability pattern, the tool can say:

```text
This finding is similar to CVE patterns related to SQL injection, but it is not a confirmed CVE match.
```

## Example Findings

### Example 1: SQL Injection

```text
File: app/routes.py
Issue: Possible SQL Injection
Severity: High
Related CWE: CWE-89
Reason: User input is directly joined into an SQL query.
Fix: Use parameterized queries.
```

### Example 2: Command Injection

```text
File: scripts/ping.py
Issue: Possible Command Injection
Severity: High
Related CWE: CWE-78
Reason: User input is passed into a shell command.
Fix: Avoid shell=True and pass arguments as a list.
```

### Example 3: Vulnerable Dependency

```text
File: requirements.txt
Package: flask
Installed version: old version
Issue: Known vulnerable dependency
Severity: Critical
Related CVE: Confirmed CVE match
Fix: Upgrade to a patched version.
```

## Agent Prompting Strategy

The model should receive structured findings.

Example prompt:

```text
You are HermesSec, a defensive security assistant.
Explain the following scanner finding for a developer.
Do not invent CVEs.
Only mention a CVE if it is present in the scanner evidence.
If this is a code pattern, map it to CWE when possible.
Give a short fix suggestion.

Finding:
{finding_json}
```

## Safety Rules

The tool should stay defensive.

It should:

- Scan code
- Explain vulnerabilities
- Suggest secure fixes
- Link to CVE or CWE context
- Help developers improve code

It should not:

- Generate exploit code
- Attack live targets
- Run destructive commands
- Claim a vulnerability is confirmed without evidence
- Send full private code to a model without user consent

## Privacy Notes

Some users may scan private repositories.

The tool should clearly show:

- Which model provider is being used
- Whether code snippets are sent to the model
- How much context is sent
- Whether results are stored locally

For privacy, the tool should prefer sending only scanner evidence and small code snippets around the issue.

## Possible Folder Structure

```text
hermsec/
  package.json
  README.md
  src/
    index.ts
    tui/
      app.ts
      screens.ts
    scanners/
      bandit.ts
      semgrep.ts
      pipAudit.ts
      osvScanner.ts
    repo/
      clone.ts
      detect.ts
    model/
      provider.ts
      openrouter.ts
      ollama.ts
      lmstudio.ts
    report/
      markdown.ts
      json.ts
      terminal.ts
    types/
      finding.ts
      scan.ts
  rules/
    semgrep/
  examples/
    vulnerable-python-app/
  reports/
```

## Core Data Types

### Finding

```ts
type Finding = {
  id: string;
  sourceTool: "bandit" | "semgrep" | "pip-audit" | "osv-scanner";
  type: "code" | "dependency";
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  file?: string;
  line?: number;
  packageName?: string;
  installedVersion?: string;
  cve?: string;
  cwe?: string;
  evidence: string;
  explanation?: string;
  suggestedFix?: string;
  confidence?: "high" | "medium" | "low";
};
```

### ScanResult

```ts
type ScanResult = {
  repository: string;
  scannedAt: string;
  toolsUsed: string[];
  modelProvider?: string;
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};
```

## MVP Build Steps

1. Create the TypeScript project.
2. Build a command that accepts a local path or GitHub URL.
3. If input is a GitHub URL, clone it into a temporary directory.
4. Detect Python files and dependency files.
5. Run Bandit and parse JSON output.
6. Run Semgrep and parse JSON output.
7. Run pip-audit or OSV-Scanner and parse JSON output.
8. Normalize all results into one Finding format.
9. Send each finding or a batch of findings to the selected model for explanation.
10. Generate terminal, Markdown, and JSON reports.
11. Add demo repository and screenshots.

## Minimum Demo Scenario

Create or use a small intentionally vulnerable Python repository.

The repository should include:

- SQL injection example
- Unsafe subprocess command example
- Hardcoded secret example
- requirements.txt with at least one old vulnerable package

Then run:

```bash
hermsec scan ./examples/vulnerable-python-app
```

Expected demo result:

- Bandit finds code issues.
- Semgrep finds rule based issues.
- pip-audit or OSV-Scanner finds vulnerable dependency.
- AI model explains the findings.
- Markdown report is generated.

## Lab 5 Two Slide Content

### Slide 1: Title And Abstract

**Title:** HermesSec TUI: A CVE Aware AI Security Agent For Repositories

**Abstract:** HermesSec TUI is a developer security assistant that scans GitHub repositories or local codebases for possible vulnerabilities. The system combines static code analysis, dependency CVE checking, and a user selected AI model to explain security risks in simple language. Instead of training a large model from scratch, the project allows users to bring their own model through OpenRouter, Ollama, LM Studio, or another compatible provider. The goal is to help developers detect risky code and vulnerable packages before pushing or releasing software.

**Key focus:**

- AI assisted secure coding
- CVE aware vulnerability checking
- Repository based security scanning
- Bring your own model support
- Developer friendly security reports

### Slide 2: Clear Idea, Tools, And Visual Demo

**Clear idea:** A user enters a GitHub URL or local repository path. The agent scans the codebase, checks dependencies against known CVEs, and creates a report showing the issue, affected file or package, severity, related CVE or CWE, and suggested fix.

**Tools and technologies:**

- Languages: Python, TypeScript
- Interface: OpenRouter Agent TUI or custom terminal UI
- AI models: OpenRouter, Ollama, LM Studio, cloud or local models
- Code scanning: Bandit, Semgrep
- Dependency scanning: pip-audit, OSV-Scanner
- Vulnerability sources: OSV.dev, NVD CVE API, GitHub Advisory Database
- Version control: Git, GitHub
- Output: JSON report, terminal report, Markdown report

**Visual demo:**

```text
GitHub URL or Local Repo
          |
          v
HermesSec TUI Agent
          |
          +--> Code Scan
          |    Bandit / Semgrep
          |
          +--> Dependency CVE Scan
          |    pip-audit / OSV-Scanner
          |
          +--> AI Explanation
          |    BYOM model
          |
          v
Security Report
Issue | File | Severity | CVE/CWE | Suggested Fix
```

## Suggested Talking Script

HermesSec is our proposed Lab 5 project. It is a terminal based AI security agent for developers. The user can give it a GitHub URL or a local repository path. The agent scans the codebase using normal security tools and checks project dependencies against vulnerability databases.

The AI model is not used blindly. Instead, the scanners create evidence and the model explains that evidence in simple language. This makes the tool more practical because developers can understand what is wrong, where the problem is, how serious it is, and how they can fix it.

The project supports bring your own model. This means users do not need to train a model or have a powerful GPU. They can use OpenRouter, Ollama, LM Studio, or another compatible provider.

For the first version, we will build a TUI because it is easy to demonstrate. Later, the same scanning engine can be used in GitHub Actions, pre-push hooks, cron jobs, or Hermes background agents.

## Comparison With PentestGPT

PentestGPT is useful as inspiration because it shows how agentic security workflows can be structured. However, HermesSec is different.

PentestGPT focuses more on penetration testing and target exploration.

HermesSec focuses on defensive repository scanning for developers.

HermesSec should not automate attacks. It should help developers find and fix vulnerabilities in their own code.

## Comparison With Hermes Agent Background Mode

The Hermes background mode idea is useful for the future.

Example:

```text
Cron job runs every night
Hermes agent scans repository
New findings are reported
Developer receives report
```

However, for Lab 5, the TUI is better because it is easier to show in a presentation.

## Final Recommended Project Goal

Build a working terminal demo that can:

1. Accept a GitHub URL or local path.
2. Scan a Python repository.
3. Detect code and dependency issues.
4. Enrich results with CVE or CWE information.
5. Use a selected AI model to explain the findings.
6. Generate a clear report.

## Success Criteria

The project is successful if:

- A user can scan a repository from the terminal.
- At least one source code vulnerability is detected.
- At least one dependency vulnerability can be reported if present.
- The output includes severity, file or package, CVE or CWE, and suggested fix.
- A Markdown report is generated.
- The demo is easy to explain in class.

## Risks And Mitigations

### Risk: CVE APIs May Be Rate Limited

Mitigation:

- Use local scanner output first.
- Cache API responses.
- Make online CVE enrichment optional.

### Risk: AI Model Hallucinates CVEs

Mitigation:

- Tell the model not to invent CVEs.
- Only pass confirmed CVEs from scanner evidence.
- Separate confirmed CVEs from similar CWE patterns.

### Risk: Repo Is Too Large

Mitigation:

- Add file limits for the demo.
- Scan only Python files first.
- Skip large folders like node_modules, venv, .git, dist, build.

### Risk: Tool Installation Problems

Mitigation:

- Provide setup instructions.
- Use Docker later if needed.
- Start with Bandit because it is easy to install.

### Risk: Private Code Privacy

Mitigation:

- Send only findings to the model.
- Add local model option.
- Warn users before using cloud models.

## First Prototype Checklist

- [ ] Create terminal project
- [ ] Add scan command
- [ ] Add GitHub clone support
- [ ] Add local path support
- [ ] Add Bandit scanner
- [ ] Add Semgrep scanner
- [ ] Add dependency scanner
- [ ] Normalize findings
- [ ] Add OpenRouter provider
- [ ] Add Ollama or LM Studio provider
- [ ] Generate Markdown report
- [ ] Create demo vulnerable repo
- [ ] Create screenshots for presentation

## Final One Sentence Pitch

HermesSec is a CVE aware AI security agent that lets developers scan repositories, find risky code and vulnerable dependencies, and receive clear fix suggestions using their own chosen AI model.
