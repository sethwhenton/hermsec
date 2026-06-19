import path from "node:path";
import { toPosixPath } from "../shared/paths.js";
import { clampText, redactSecrets, stableId } from "../shared/text.js";
import type { Finding, ScannerStatus, Severity } from "../shared/types.js";
import type { SourceFile } from "../core/files.js";

type Candidate = Omit<Finding, "id" | "fingerprint" | "tool"> & {
  tool?: string;
};

type OfflineScanner = {
  id: string;
  label: string;
  shouldRun: (files: SourceFile[]) => boolean;
  scan: (files: SourceFile[], readText: (file: SourceFile) => Promise<string>) => Promise<Finding[]>;
};

const LIFECYCLE_SCRIPTS = new Set(["preinstall", "install", "postinstall", "prepare"]);
const DEPENDENCY_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const JS_LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]);
const PYTHON_LOCKFILES = new Set(["poetry.lock", "uv.lock", "Pipfile.lock"]);

const OFFLINE_SCANNERS: OfflineScanner[] = [
  {
    id: "hermsec-secrets",
    label: "Hermsec secret heuristics",
    shouldRun: (files) => files.some(isSecretCandidate),
    scan: scanSecrets,
  },
  {
    id: "hermsec-js-ts",
    label: "Hermsec JS/TS heuristics",
    shouldRun: (files) => files.some((file) => file.language === "javascript" || file.language === "typescript"),
    scan: scanJavaScriptAndTypeScript,
  },
  {
    id: "hermsec-python",
    label: "Hermsec Python heuristics",
    shouldRun: (files) => files.some((file) => file.language === "python"),
    scan: scanPython,
  },
  {
    id: "hermsec-java",
    label: "Hermsec Java servlet heuristics",
    shouldRun: (files) => files.some((file) => file.language === "java" || file.language === "jsp"),
    scan: scanJava,
  },
  {
    id: "hermsec-packages",
    label: "Hermsec package manifest heuristics",
    shouldRun: (files) => files.some((file) => file.kind === "manifest" || file.kind === "lockfile"),
    scan: scanPackageFiles,
  },
  {
    id: "hermsec-config",
    label: "Hermsec config heuristics",
    shouldRun: (files) => files.some(isConfigCandidate),
    scan: scanConfig,
  },
];

export async function runOfflineHeuristicScanners(
  files: SourceFile[],
  readText: (file: SourceFile) => Promise<string>,
): Promise<{ findings: Finding[]; statuses: ScannerStatus[] }> {
  const findings: Finding[] = [];
  const statuses: ScannerStatus[] = [];

  for (const scanner of OFFLINE_SCANNERS) {
    if (!scanner.shouldRun(files)) {
      statuses.push({
        id: scanner.id,
        label: scanner.label,
        status: "skipped",
        message: `${scanner.label} had no matching inputs.`,
      });
      continue;
    }

    const started = Date.now();
    try {
      const scannerFindings = await scanner.scan(files, readText);
      findings.push(...scannerFindings);
      statuses.push({
        id: scanner.id,
        label: scanner.label,
        status: "completed",
        message: `${scanner.label} completed with ${scannerFindings.length} finding${scannerFindings.length === 1 ? "" : "s"}.`,
        durationMs: Date.now() - started,
      });
    } catch (error) {
      statuses.push({
        id: scanner.id,
        label: scanner.label,
        status: "failed",
        message: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - started,
      });
    }
  }

  return {
    findings,
    statuses,
  };
}

export function scanFile(relativePath: string, content: string): Finding[] {
  const normalized = toPosixPath(relativePath);
  const file: SourceFile = {
    absolutePath: normalized,
    relativePath: normalized,
    extension: path.extname(normalized).toLowerCase(),
    baseName: path.basename(normalized),
    size: content.length,
    language: languageFromPath(normalized),
    kind: "source",
  };
  return [
    ...scanSecretContent(file, content),
    ...scanCodeContent(file, content),
    ...scanPythonContent(file, content),
    ...scanJavaContent(file, content),
    ...scanConfigContent(file, content),
  ].map(finalizeFinding);
}

async function scanSecrets(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter(isSecretCandidate)) {
    const content = await readText(file);
    candidates.push(...scanSecretContent(file, content));
  }
  return candidates.map(finalizeFinding);
}

function scanSecretContent(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];
  const privateKeyLine = firstLineMatching(content, /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/);
  if (privateKeyLine !== undefined) {
    findings.push({
      title: "Private key material in repository",
      category: "secret",
      severity: "critical",
      confidence: "high",
      description: "A private key block was found in a file that is part of the scan target.",
      evidence: `${file.relativePath}:${privateKeyLine} contains a private key block.`,
      remediation: "Remove the key, rotate any dependent credentials, and store private keys outside the repository.",
      location: { file: file.relativePath, startLine: privateKeyLine },
      cwe: ["CWE-798"],
      ruleId: "hermsec.secret.private-key",
    });
  }

  for (const { line, number } of linesOf(content)) {
    if (/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(line)) {
      findings.push(secretFinding(file, number, line, "Possible AWS access key", "high", "high", "hermsec.secret.aws-access-key"));
    }
    if (/\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/.test(line)) {
      findings.push(secretFinding(file, number, line, "Possible GitHub token", "high", "high", "hermsec.secret.github-token"));
    }
    if (/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(line)) {
      findings.push(secretFinding(file, number, line, "Possible Slack token", "high", "high", "hermsec.secret.slack-token"));
    }

    const generic = /\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{20,})/i.exec(line);
    const genericValue = generic?.[1];
    if (genericValue && !isLikelyPlaceholder(genericValue)) {
      findings.push(secretFinding(
        file,
        number,
        line,
        "Possible hardcoded secret",
        file.baseName.includes("example") ? "low" : "medium",
        file.baseName.includes("example") ? "low" : "medium",
        "hermsec.secret.literal",
      ));
    }
    if (/HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE[A-Za-z0-9_-]*/.test(line)) {
      findings.push(secretFinding(
        file,
        number,
        line,
        "Hermsec fake secret fixture token",
        "high",
        "confirmed",
        "hermsec.secret.fake-fixture-token",
      ));
    }
  }
  return findings;
}

async function scanJavaScriptAndTypeScript(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter((item) => item.language === "javascript" || item.language === "typescript")) {
    if (file.relativePath.endsWith(".d.ts") || isMinifiedJavaScriptAsset(file)) {
      continue;
    }
    candidates.push(...scanCodeContent(file, await readText(file)));
  }
  return candidates.map(finalizeFinding);
}

function scanCodeContent(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];
  if (file.language !== "javascript" && file.language !== "typescript") {
    return findings;
  }

  for (const { line, number } of linesOf(content)) {
    if (/\beval\s*\(/.test(line)) {
      findings.push(codeFinding("Dynamic code execution with eval", "high", "CWE-95", file, number, line, "Replace eval with structured parsing or explicit dispatch.", "hermsec.code.eval"));
    }
    if (/\bnew\s+Function\s*\(/.test(line)) {
      findings.push(codeFinding("Dynamic code execution with Function constructor", "high", "CWE-95", file, number, line, "Avoid string-to-code conversion.", "hermsec.code.function-constructor"));
    }
    if (/\b(?:child_process\.)?(?:exec|execSync)\s*\(/.test(line)) {
      findings.push(codeFinding("Shell execution through child_process", "high", "CWE-78", file, number, line, "Use spawn or execFile with fixed argv arrays and shell disabled.", "hermsec.code.child-process-exec"));
    }
    if (/\bexec\s*\(.*(?:req\.|query|params|body|input|\$\{)/.test(line)) {
      findings.push(codeFinding("Shell execution may include user-controlled input", "critical", "CWE-78", file, number, line, "Use fixed argv arrays and validate user-controlled values before execution.", "hermsec.code.command-injection-input"));
    }
    if (/\bshell\s*:\s*true\b/.test(line)) {
      findings.push(codeFinding("Child process shell mode enabled", "medium", "CWE-78", file, number, line, "Keep shell mode disabled and pass arguments as arrays.", "hermsec.code.shell-true"));
    }
    if (/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/.test(line)) {
      findings.push(codeFinding("TLS certificate verification disabled", "high", "CWE-295", file, number, line, "Remove this setting and fix certificate trust configuration.", "hermsec.code.node-tls-disabled"));
    }
    if (/\borigin\s*:\s*["']\*["']/.test(line)) {
      findings.push(codeFinding("Wildcard CORS origin", "medium", "CWE-942", file, number, line, "Restrict CORS origins to trusted application domains.", "hermsec.code.cors-wildcard"));
    }
    if (/\.innerHTML\s*=/.test(line)) {
      findings.push(codeFinding("Direct innerHTML assignment", "medium", "CWE-79", file, number, line, "Use textContent for plain text or sanitize trusted HTML.", "hermsec.code.inner-html"));
    }
    if (/(?:res\.send|reply\.send)\s*\(.*(?:req\.|query|params|body|\$\{)/.test(line)) {
      findings.push(codeFinding("HTML response may include unsanitized input", "medium", "CWE-79", file, number, line, "Escape untrusted output before placing it in HTML responses.", "hermsec.code.unsanitized-html-response"));
    }
    if (/(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|\$\{|`)/i.test(line)) {
      findings.push(codeFinding("SQL query appears to include dynamic string construction", "high", "CWE-89", file, number, line, "Use parameterized queries or a query builder.", "hermsec.code.sql-dynamic-string"));
    }
  }
  return findings;
}

async function scanPython(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter((item) => item.language === "python")) {
    candidates.push(...scanPythonContent(file, await readText(file)));
  }
  return candidates.map(finalizeFinding);
}

function scanPythonContent(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];
  if (file.language !== "python") {
    return findings;
  }

  for (const { line, number } of linesOf(content)) {
    if (/\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True/.test(line)) {
      findings.push(codeFinding("Subprocess shell mode enabled", "high", "CWE-78", file, number, line, "Use subprocess with argv arrays and shell=False.", "hermsec.python.subprocess-shell"));
    }
    if (/\bos\.system\s*\(/.test(line)) {
      findings.push(codeFinding("Shell execution with os.system", "high", "CWE-78", file, number, line, "Use subprocess.run with fixed argv arrays and shell disabled.", "hermsec.python.os-system"));
    }
    if (/\b(?:eval|exec)\s*\(/.test(line)) {
      findings.push(codeFinding("Dynamic Python code execution", "high", "CWE-95", file, number, line, "Replace dynamic execution with safe parsing or explicit dispatch.", "hermsec.python.eval-exec"));
    }
    if (/\bpickle\.loads?\s*\(/.test(line)) {
      findings.push(codeFinding("Unsafe pickle deserialization", "medium", "CWE-502", file, number, line, "Use JSON or another safe data format for untrusted input.", "hermsec.python.pickle"));
    }
    if (/\byaml\.load\s*\((?!.*(?:SafeLoader|safe_load))/.test(line)) {
      findings.push(codeFinding("Potentially unsafe YAML loading", "high", "CWE-502", file, number, line, "Use yaml.safe_load or pass SafeLoader explicitly.", "hermsec.python.yaml-load"));
    }
    if (/\bverify\s*=\s*False\b/.test(line)) {
      findings.push(codeFinding("TLS verification disabled", "medium", "CWE-295", file, number, line, "Keep TLS verification enabled.", "hermsec.python.verify-false"));
    }
    if (/\bdebug\s*=\s*True\b/.test(line)) {
      findings.push(codeFinding("Debug mode enabled", "medium", "CWE-489", file, number, line, "Disable debug mode outside local development.", "hermsec.python.debug-true"));
    }
  }
  return findings;
}

async function scanJava(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter((item) => item.language === "java" || item.language === "jsp")) {
    candidates.push(...scanJavaContent(file, await readText(file)));
  }
  return candidates.map(finalizeFinding);
}

function scanJavaContent(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];
  if (file.language !== "java" && file.language !== "jsp") {
    return findings;
  }

  const flat = compactWhitespace(content);
  const taint = analyzeJavaTaint(content);
  const add = (
    title: string,
    severity: Severity,
    cwe: string,
    linePattern: RegExp,
    remediation: string,
    ruleId: string,
  ): void => {
    const line = firstLineMatching(content, linePattern);
    findings.push(codeFinding(
      title,
      severity,
      cwe,
      file,
      line,
      line === undefined ? `Matched Java sink pattern for ${ruleId}.` : lineAt(content, line),
      remediation,
      ruleId,
    ));
  };

  if (taint.lineFor(/(?:\b\w+\.exec\s*\(|Runtime\.getRuntime\(\)\.exec|new\s+(?:java\.lang\.)?ProcessBuilder\b|\bProcessBuilder\s+\w+|\.start\s*\(\s*\))/)) {
    add(
      "Java process execution reachable in servlet code",
      "high",
      "CWE-78",
      /(?:\b\w+\.exec\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.start\s*\()/,
      "Avoid shell/process execution with request-influenced data; use fixed command allowlists and fixed argument arrays.",
      "hermsec.java.cmdi",
    );
  }

  if (/(?:Cipher|KeyGenerator)\.getInstance\s*\(\s*"(?:DES|DESede|RC[24]|AES\/ECB|AES\/CBC|RSA\/ECB)/i.test(content)) {
    add(
      "Weak Java cryptographic primitive or mode",
      "high",
      "CWE-327",
      /(?:Cipher|KeyGenerator)\.getInstance/,
      "Use modern authenticated encryption such as AES-GCM with unique nonces and project-approved key management.",
      "hermsec.java.crypto",
    );
  }

  if (/MessageDigest\.getInstance\s*\(\s*(?:"(?:MD2|MD4|MD5|SHA-?1)"|algorithm)/i.test(content) || /getProperty\("hashAlg1"/.test(content)) {
    add(
      "Weak Java message digest for security-sensitive data",
      "high",
      "CWE-328",
      /MessageDigest\.getInstance|getProperty\("hashAlg1"/,
      "Use a strong password hashing or digest strategy appropriate to the data, such as Argon2/bcrypt for passwords.",
      "hermsec.java.hash",
    );
  }

  if (/(?:new\s+java\.util\.Random\s*\(|new\s+Random\s*\(|Math\.random\s*\(|java\.util\.Random\s+\w+)/.test(content)) {
    add(
      "Predictable random value used in Java code",
      "medium",
      "CWE-330",
      /(?:new\s+java\.util\.Random\s*\(|new\s+Random\s*\(|Math\.random\s*\(|java\.util\.Random\s+\w+)/,
      "Use java.security.SecureRandom for tokens, cookies, keys, and other security-sensitive randomness.",
      "hermsec.java.weakrand",
    );
  }

  if (/new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/.test(content) && !/\.setSecure\s*\(\s*true\s*\)/.test(content)) {
    add(
      "Servlet cookie is added without Secure flag",
      "medium",
      "CWE-614",
      /new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/,
      "Set Secure and HttpOnly on sensitive cookies, and review SameSite/path/domain scope.",
      "hermsec.java.securecookie",
    );
  }

  if (taint.lineFor(/(?:getSession\(\)|\bsession)\s*\.\s*(?:setAttribute|putValue)\s*\(/i)) {
    add(
      "Request data may cross into the Java session boundary",
      "medium",
      "CWE-501",
      /getSession\(\)\.(?:setAttribute|putValue)\s*\(/,
      "Validate and constrain request-derived session keys and values before storing them in the session.",
      "hermsec.java.trustbound",
    );
  }

  if (taint.lineFor(/\.(?:executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareCall|prepareStatement|createQuery|createNativeQuery)\s*\(/)) {
    add(
      "Java SQL query uses dynamic string construction",
      "high",
      "CWE-89",
      /(?:prepareCall|prepareStatement|executeQuery|executeUpdate|execute)\s*\(/,
      "Use parameterized queries with placeholders and keep untrusted input out of SQL structure.",
      "hermsec.java.sqli",
    );
  }

  if (taint.lineFor(/\.(?:search|lookup|list|listBindings)\s*\(/)) {
    add(
      "Java LDAP filter uses dynamic string construction",
      "high",
      "CWE-90",
      /\.search\s*\(/,
      "Build LDAP filters with safe escaping or parameterized APIs for every untrusted value.",
      "hermsec.java.ldapi",
    );
  }

  if (taint.lineFor(/\.(?:evaluate|compile)\s*\(/)) {
    add(
      "Java XPath expression uses dynamic string construction",
      "high",
      "CWE-643",
      /\.evaluate\s*\(/,
      "Avoid concatenating untrusted input into XPath expressions; escape values or use a safe query construction API.",
      "hermsec.java.xpathi",
    );
  }

  if (
    /(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|new\s+java\.io\.File|Paths\.get|Files\.(?:newInputStream|newOutputStream|readAllBytes|readString|write|copy|delete))\s*\(/.test(flat) &&
    taint.lineFor(/(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|new\s+java\.io\.File|Paths\.get|Files\.(?:newInputStream|newOutputStream|readAllBytes|readString|write|copy|delete))\s*\(/)
  ) {
    add(
      "Java file path uses request-influenced data",
      "high",
      "CWE-22",
      /(?:FileInputStream|FileOutputStream|FileReader|FileWriter|new\s+java\.io\.File|Paths\.get)\s*\(/,
      "Resolve paths against an allowlisted base directory, normalize, and reject paths that escape the expected root.",
      "hermsec.java.pathtraver",
    );
  }

  if (
    taint.lineFor(/(?:response\.getWriter\(\)\.(?:print|println|write|format)|response\.(?:sendRedirect|sendError|addHeader|setHeader|setDateHeader|setIntHeader))\s*\(/, { ignoreSanitizedLine: true })
  ) {
    add(
      "Java servlet response may include unsanitized input",
      "medium",
      "CWE-79",
      /response\.getWriter\(\)\.(?:print|println|write|format)\s*\(/,
      "HTML-encode untrusted values before writing them to servlet responses, or render through an escaping template engine.",
      "hermsec.java.xss",
    );
  }

  return findings;
}

type JavaTaintContext = {
  taintedVariables: Set<string>;
  sanitizedVariables: Set<string>;
  lineFor: (sink: RegExp, options?: { ignoreSanitizedLine?: boolean }) => number | undefined;
};

type JavaStatement = {
  text: string;
  startLine: number;
};

function analyzeJavaTaint(content: string): JavaTaintContext {
  const taintedVariables = new Set<string>();
  const sanitizedVariables = new Set<string>();
  const sourceLikeVariables = new Set(["param", "bar", "input", "query", "cmd", "command", "fileName", "path", "sql", "filter", "expression"]);
  const lines = linesOf(content);
  const statements = javaStatements(lines);

  for (const statement of statements) {
    const assignment = assignmentParts(statement.text);
    if (!assignment) {
      const append = statement.text.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:append|add|concat)\s*\((.+)\)/);
      if (append?.[1] && append[2] && (isJavaRequestSourceExpression(append[2]) || expressionReferencesAny(append[2], taintedVariables))) {
        taintedVariables.add(append[1]);
        sanitizedVariables.delete(append[1]);
      }
      continue;
    }
    const { name, expression } = assignment;
    if (isJavaSanitizerExpression(expression)) {
      sanitizedVariables.add(name);
      taintedVariables.delete(name);
      continue;
    }
    if (isJavaRequestSourceExpression(expression) || expressionReferencesAny(expression, taintedVariables)) {
      taintedVariables.add(name);
      sanitizedVariables.delete(name);
      continue;
    }
    if (sourceLikeVariables.has(name) && /(?:request|header|parameter|cookie|query|string|input|value)/i.test(expression)) {
      taintedVariables.add(name);
    }
  }

  const context: JavaTaintContext = {
    taintedVariables,
    sanitizedVariables,
    lineFor: (sink, options) => {
      for (const statement of statements) {
        if (!sink.test(statement.text)) {
          continue;
        }
        if (options?.ignoreSanitizedLine && isJavaSanitizerExpression(statement.text)) {
          continue;
        }
        if (isJavaRequestSourceExpression(statement.text) || expressionReferencesAny(statement.text, taintedVariables)) {
          return statement.startLine;
        }
      }
      return undefined;
    },
  };
  return context;
}

function assignmentParts(line: string): { name: string; expression: string } | undefined {
  const match = compactWhitespace(line).match(/(?:^|[;\s])(?:final\s+)?(?:String|Object|File|Path|StringBuilder|StringBuffer|byte\[\]|char\[\]|java\.lang\.String|java\.io\.File|java\.nio\.file\.Path)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?\s*$/);
  if (!match?.[1] || !match[2]) {
    return undefined;
  }
  return { name: match[1], expression: match[2] };
}

function isJavaRequestSourceExpression(expression: string): boolean {
  return /\brequest\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getInputStream|getReader|getAttribute|getPathInfo|getPathTranslated|getRequestURI|getRequestURL|getServletPath|getRemoteUser|getRequestedSessionId|getPart|getParts)\s*\(/.test(expression) ||
    /\b(?:HttpServletRequest|ServletRequest)\b/.test(expression) ||
    /\b[A-Za-z_][A-Za-z0-9_]*Cookie\.getValue\s*\(/.test(expression) ||
    (/\bgetValue\s*\(/.test(expression) && /\bCookie\b|cookie/i.test(expression));
}

function isJavaSanitizerExpression(expression: string): boolean {
  return /(?:ESAPI\.encoder\(\)\.encodeFor(?:HTML|HTMLAttribute|JavaScript|URL|LDAP|SQL|XPath)|Encode\.for(?:Html|HtmlContent|HtmlAttribute|JavaScript|UriComponent|Xml)|StringEscapeUtils\.escape(?:Html|Html4|Xml|EcmaScript|JavaScript|Sql)|HtmlUtils\.htmlEscape|Utils\.encodeForHTML|escapeHtml|htmlEscape|URLEncoder\.encode|Normalizer\.normalize)\s*\(/.test(expression);
}

function javaStatements(lines: Array<{ line: string; number: number }>): JavaStatement[] {
  const statements: JavaStatement[] = [];
  let current = "";
  let startLine: number | undefined;

  for (const { line, number } of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) {
      continue;
    }
    startLine ??= number;
    current = `${current} ${trimmed}`.trim();
    if (/[;{}]\s*$/.test(trimmed)) {
      statements.push({ text: current, startLine });
      current = "";
      startLine = undefined;
    }
  }

  if (current && startLine !== undefined) {
    statements.push({ text: current, startLine });
  }
  return statements;
}

function expressionReferencesAny(expression: string, variables: ReadonlySet<string>): boolean {
  for (const variable of variables) {
    if (new RegExp(`\\b${escapeRegExp(variable)}\\b`).test(expression)) {
      return true;
    }
  }
  return false;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function scanPackageFiles(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter((item) => item.kind === "manifest" || item.kind === "lockfile")) {
    const content = await readText(file);
    if (file.baseName === "package.json") {
      candidates.push(...scanPackageJson(file, content, files));
    } else if (file.baseName === "package-lock.json" || file.baseName === "npm-shrinkwrap.json") {
      candidates.push(...scanPackageLock(file, content));
    } else if (file.baseName === "requirements.txt" || file.baseName === "requirements-dev.txt") {
      candidates.push(...scanRequirements(file, content));
    } else if (file.baseName === "pyproject.toml") {
      candidates.push(...scanPyproject(file, content, files));
    }
  }
  return candidates.map(finalizeFinding);
}

function scanPackageJson(file: SourceFile, content: string, files: SourceFile[]): Candidate[] {
  const parsed = parseJsonRecord(content);
  if (!parsed) {
    return [];
  }

  const findings: Candidate[] = [];
  const scripts = isRecord(parsed.scripts) ? parsed.scripts : {};
  for (const [scriptName, scriptValue] of stringEntries(scripts)) {
    const line = lineNumberContaining(content, `"${scriptName}"`);
    if (LIFECYCLE_SCRIPTS.has(scriptName)) {
      findings.push({
        title: "Install lifecycle script in package manifest",
        category: "supply-chain",
        severity: scriptName === "postinstall" ? "high" : "medium",
        confidence: "high",
        description: "Install lifecycle scripts execute during dependency installation and can run arbitrary code.",
        evidence: evidenceFor(file, line, `"${scriptName}": "${scriptValue}"`),
        remediation: "Avoid install-time lifecycle scripts unless strictly necessary and documented.",
        location: locationFor(file, line),
        cwe: ["CWE-829"],
        ruleId: "hermsec.package.lifecycle-script",
      });
    }
    if (/(?:curl|wget)\b.*\|\s*(?:bash|sh|node|python)|(?:bash|sh)\s+-c\s+["']/.test(scriptValue)) {
      findings.push({
        title: "Package script executes downloaded or shell code",
        category: "supply-chain",
        severity: "high",
        confidence: "medium",
        description: "Package scripts that pipe downloaded content to an interpreter or invoke shell command strings increase supply-chain risk.",
        evidence: evidenceFor(file, line, `"${scriptName}": "${scriptValue}"`),
        remediation: "Replace remote script execution with pinned, reviewed tooling and fixed argument arrays.",
        location: locationFor(file, line),
        cwe: ["CWE-829"],
        ruleId: "hermsec.package.remote-script-execution",
      });
    }
  }

  for (const section of DEPENDENCY_SECTIONS) {
    for (const [packageName, specifier] of stringEntries(parsed[section])) {
      const risk = dependencySpecifierRisk(specifier);
      if (!risk) {
        continue;
      }
      const line = lineNumberContaining(content, `"${packageName}"`);
      findings.push({
        title: "Risky dependency specifier",
        category: "supply-chain",
        severity: risk.severity,
        confidence: "medium",
        description: risk.description,
        evidence: evidenceFor(file, line, `"${packageName}": "${specifier}"`),
        remediation: "Prefer registry packages pinned through a committed lockfile; document unavoidable non-registry dependencies.",
        location: locationFor(file, line),
        package: { ecosystem: "npm", name: packageName, installedVersion: specifier },
        cwe: ["CWE-829"],
        ruleId: "hermsec.package.risky-specifier",
      });
    }
  }

  if (hasDependencyEntries(parsed) && !hasLockfileForDirectory(file, files, JS_LOCKFILES)) {
    findings.push({
      title: "JavaScript dependencies without a committed lockfile",
      category: "supply-chain",
      severity: "info",
      confidence: "high",
      description: "A package manifest with dependencies was found without a package manager lockfile in the same directory.",
      evidence: `${file.relativePath} declares dependencies but no npm, pnpm, yarn, or bun lockfile was found beside it.`,
      remediation: "Commit the appropriate lockfile after dependency review; do not generate one during scanning.",
      location: { file: file.relativePath },
      ruleId: "hermsec.package.missing-js-lockfile",
    });
  }

  return findings;
}

function scanPackageLock(file: SourceFile, content: string): Candidate[] {
  const parsed = parseJsonRecord(content);
  if (!parsed) {
    return [];
  }
  const findings: Candidate[] = [];

  if (typeof parsed.lockfileVersion === "number" && parsed.lockfileVersion < 2) {
    findings.push({
      title: "Old npm lockfile format",
      category: "supply-chain",
      severity: "low",
      confidence: "high",
      description: "Old npm lockfile formats contain less package metadata for deterministic auditing.",
      evidence: `${file.relativePath} uses lockfileVersion ${parsed.lockfileVersion}.`,
      remediation: "Review and update the lockfile with a modern npm version when it is safe to do so.",
      location: { file: file.relativePath },
      ruleId: "hermsec.package.old-lockfile",
    });
  }

  const packages = isRecord(parsed.packages) ? parsed.packages : {};
  let installScriptFindings = 0;
  for (const [packagePath, rawPackage] of Object.entries(packages)) {
    if (!isRecord(rawPackage) || packagePath === "") {
      continue;
    }
    const packageName = typeof rawPackage.name === "string" ? rawPackage.name : packagePath.replace(/^node_modules\//, "");
    if (rawPackage.hasInstallScript === true && installScriptFindings < 25) {
      installScriptFindings += 1;
      findings.push({
        title: "Dependency declares an install script",
        category: "supply-chain",
        severity: "medium",
        confidence: "high",
        description: "The lockfile records a dependency with an install script. Hermsec does not execute it, but installs may.",
        evidence: `${file.relativePath} marks ${packageName} as hasInstallScript=true.`,
        remediation: "Review the package and keep installs configured with ignore-scripts unless the script is explicitly trusted.",
        location: { file: file.relativePath },
        package: packageInfo("npm", packageName, rawPackage.version),
        cwe: ["CWE-829"],
        ruleId: "hermsec.package.lockfile-install-script",
      });
    }

    if (typeof rawPackage.resolved === "string" && rawPackage.resolved.startsWith("http://")) {
      findings.push({
        title: "Lockfile resolves dependency over HTTP",
        category: "supply-chain",
        severity: "high",
        confidence: "high",
        description: "A lockfile entry resolves over plaintext HTTP, allowing dependency tampering in transit.",
        evidence: `${file.relativePath} resolves ${packageName} from ${rawPackage.resolved}.`,
        remediation: "Use HTTPS registry URLs and regenerate the lockfile only after review.",
        location: { file: file.relativePath },
        package: packageInfo("npm", packageName, rawPackage.version),
        cwe: ["CWE-494"],
        ruleId: "hermsec.package.insecure-lock-url",
      });
    }
    if (packageName === "lodash" && typeof rawPackage.version === "string" && isVersionBelow(rawPackage.version, "4.17.21")) {
      findings.push({
        title: "Known vulnerable lodash version",
        category: "dependency",
        severity: "high",
        confidence: "high",
        description: "The lockfile pins lodash below 4.17.21, a version range with known advisories.",
        evidence: `${file.relativePath} pins lodash@${rawPackage.version}.`,
        remediation: "Upgrade lodash to 4.17.21 or newer after dependency review.",
        location: { file: file.relativePath },
        package: packageInfo("npm", "lodash", rawPackage.version),
        identifiers: { ghsa: ["GHSA-35jh-r3h4-6jhm"] },
        cwe: ["CWE-79"],
        ruleId: "hermsec.package.lodash-known-vulnerable",
      });
    }
  }

  return findings;
}

function scanRequirements(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];
  for (const { line, number } of linesOf(content)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-r ") || trimmed.startsWith("--")) {
      continue;
    }
    if (/^(?:git\+|https?:\/\/)/i.test(trimmed)) {
      findings.push({
        title: "Python requirement uses a remote URL",
        category: "supply-chain",
        severity: trimmed.startsWith("http://") ? "high" : "medium",
        confidence: "medium",
        description: "Direct URL requirements bypass normal registry resolution and can be harder to audit.",
        evidence: evidenceFor(file, number, trimmed),
        remediation: "Prefer registry packages pinned with hashes; document any unavoidable URL dependency.",
        location: locationFor(file, number),
        cwe: ["CWE-829"],
        ruleId: "hermsec.package.python-url-requirement",
      });
      continue;
    }
    if (!/^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[^=<>!~]+/.test(trimmed)) {
      findings.push({
        title: "Unpinned Python requirement",
        category: "supply-chain",
        severity: "low",
        confidence: "medium",
        description: "Unpinned requirements can resolve to different package versions across installs.",
        evidence: evidenceFor(file, number, trimmed),
        remediation: "Pin reviewed package versions and use hash checking for higher assurance.",
        location: locationFor(file, number),
        package: { ecosystem: "pypi", name: trimmed.split(/[<>=!~\s\[]/, 1)[0] ?? trimmed },
        ruleId: "hermsec.package.unpinned-python",
      });
    }
  }
  return findings;
}

function scanPyproject(file: SourceFile, content: string, files: SourceFile[]): Candidate[] {
  if (!/\bdependencies\s*=/.test(content) || hasLockfileForDirectory(file, files, PYTHON_LOCKFILES)) {
    return [];
  }
  return [{
    title: "Python project dependencies without a recognized lockfile",
    category: "supply-chain",
    severity: "info",
    confidence: "medium",
    description: "A Python project manifest declares dependencies without a recognized lockfile beside it.",
    evidence: `${file.relativePath} declares dependencies but no poetry.lock, uv.lock, or Pipfile.lock was found beside it.`,
    remediation: "Use a reviewed lockfile for reproducible installs where the project workflow supports one.",
    location: { file: file.relativePath },
    ruleId: "hermsec.package.missing-python-lockfile",
  }];
}

async function scanConfig(files: SourceFile[], readText: (file: SourceFile) => Promise<string>): Promise<Finding[]> {
  const candidates: Candidate[] = [];
  for (const file of files.filter(isConfigCandidate)) {
    candidates.push(...scanConfigContent(file, await readText(file)));
  }
  return candidates.map(finalizeFinding);
}

function scanConfigContent(file: SourceFile, content: string): Candidate[] {
  const findings: Candidate[] = [];

  if (isCommittedEnvFile(file)) {
    findings.push({
      title: "Environment file in scan target",
      category: "config",
      severity: "medium",
      confidence: "medium",
      description: "Environment files often contain local secrets or deployment-specific settings.",
      evidence: `${file.relativePath} appears to be a committed environment file.`,
      remediation: "Keep real environment files out of source control and commit only sanitized examples.",
      location: { file: file.relativePath },
      cwe: ["CWE-312"],
      ruleId: "hermsec.config.env-file",
    });
  }

  for (const { line, number } of linesOf(content)) {
    if (isGitHubWorkflow(file) && /\bpull_request_target\b/.test(line)) {
      findings.push(configFinding("High-risk GitHub Actions trigger", "medium", "CWE-829", file, number, line, "Use pull_request for untrusted code, or keep pull_request_target jobs minimal.", "hermsec.config.pull-request-target"));
    }
    if (isGitHubWorkflow(file) && /\bpermissions\s*:\s*write-all\b/.test(line)) {
      findings.push(configFinding("Broad GitHub Actions write permissions", "high", "CWE-266", file, number, line, "Set top-level permissions to contents: read and grant minimal per-job permissions.", "hermsec.config.write-all"));
    }
    if (isGitHubWorkflow(file) && /\bpersist-credentials\s*:\s*true\b/.test(line)) {
      findings.push(configFinding("Checkout persists Git credentials", "medium", "CWE-522", file, number, line, "Set persist-credentials: false unless a job explicitly needs to push.", "hermsec.config.persist-credentials"));
    }
    if (isComposeFile(file) && /\bprivileged\s*:\s*true\b/.test(line)) {
      findings.push(configFinding("Privileged container enabled", "high", "CWE-250", file, number, line, "Remove privileged mode and grant only specific capabilities.", "hermsec.config.privileged-container"));
    }
    if (isComposeFile(file) && /\bnetwork_mode\s*:\s*["']?host["']?/.test(line)) {
      findings.push(configFinding("Container uses host networking", "medium", "CWE-668", file, number, line, "Use a dedicated Docker network and expose only required ports.", "hermsec.config.host-network"));
    }
    if (isDockerfile(file) && /\b(?:curl|wget)\b.*\|\s*(?:bash|sh)\b/.test(line)) {
      findings.push(configFinding("Dockerfile pipes remote script to shell", "high", "CWE-829", file, number, line, "Download pinned artifacts, verify them, and execute reviewed local scripts.", "hermsec.config.curl-pipe-shell"));
    }
    if (isDockerfile(file) && /^\s*ADD\s+https?:\/\//i.test(line)) {
      findings.push(configFinding("Dockerfile ADD uses remote URL", "medium", "CWE-829", file, number, line, "Fetch reviewed artifacts explicitly and COPY local files into the image.", "hermsec.config.add-remote-url"));
    }
    if (/\b(?:strict-ssl|verify_ssl|ssl_verify|tls_verify)\s*[:=]\s*false\b/i.test(line)) {
      findings.push(configFinding("TLS verification disabled in configuration", "medium", "CWE-295", file, number, line, "Keep TLS verification enabled and configure trusted certificate authorities.", "hermsec.config.tls-disabled"));
    }
  }

  return findings;
}

function secretFinding(
  file: SourceFile,
  lineNumber: number,
  evidence: string,
  title: string,
  severity: Severity,
  confidence: Finding["confidence"],
  ruleId: string,
): Candidate {
  return {
    title,
    category: "secret",
    severity,
    confidence,
    description: "A secret-like value is present in source control.",
    evidence: evidenceFor(file, lineNumber, evidence),
    remediation: "Move secrets to environment variables or a secret manager and rotate exposed credentials.",
    location: locationFor(file, lineNumber),
    cwe: ["CWE-798"],
    ruleId,
  };
}

function codeFinding(title: string, severity: Severity, cwe: string, file: SourceFile, lineNumber: number | undefined, evidence: string, remediation: string, ruleId: string): Candidate {
  return {
    title,
    category: "code",
    severity,
    confidence: "medium",
    description: "Hermsec's offline heuristic scanner found a risky source pattern.",
    evidence: evidenceFor(file, lineNumber, evidence),
    remediation,
    location: locationFor(file, lineNumber),
    cwe: [cwe],
    ruleId,
  };
}

function configFinding(title: string, severity: Severity, cwe: string, file: SourceFile, lineNumber: number, evidence: string, remediation: string, ruleId: string): Candidate {
  return {
    title,
    category: "config",
    severity,
    confidence: "medium",
    description: "Hermsec's offline config scanner found a risky setting.",
    evidence: evidenceFor(file, lineNumber, evidence),
    remediation,
    location: locationFor(file, lineNumber),
    cwe: [cwe],
    ruleId,
  };
}

function finalizeFinding(candidate: Candidate): Finding {
  const fingerprintSource = JSON.stringify({
    ruleId: candidate.ruleId,
    category: candidate.category,
    file: candidate.location?.file,
    line: candidate.location?.startLine,
    package: candidate.package,
    title: candidate.title,
  });
  const fingerprint = stableId(fingerprintSource, "fp");
  return {
    ...candidate,
    tool: candidate.tool ?? "hermsec-offline",
    evidence: redactSensitiveEvidence(clampText(candidate.evidence, 500)),
    id: stableId(fingerprintSource, "finding"),
    fingerprint,
  };
}

function redactSensitiveEvidence(value: string): string {
  return redactSecrets(value)
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_KEY]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g, "gh_[REDACTED]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "xox-[REDACTED]");
}

function parseJsonRecord(content: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(content);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function dependencySpecifierRisk(specifier: string): { severity: Severity; description: string } | undefined {
  if (/^(?:git\+|github:)/i.test(specifier)) {
    return { severity: "medium", description: "Git-based dependency specifiers are mutable unless pinned to immutable commits and reviewed." };
  }
  if (/^http:\/\//i.test(specifier)) {
    return { severity: "high", description: "Plain HTTP dependency specifiers can be tampered with in transit." };
  }
  if (/^(?:https?:\/\/|file:|link:|workspace:)/i.test(specifier)) {
    return { severity: "medium", description: "Non-registry dependency specifiers reduce reproducibility and may bypass normal package review." };
  }
  return undefined;
}

function packageInfo(ecosystem: string, name: string, version: unknown): NonNullable<Finding["package"]> {
  const info: NonNullable<Finding["package"]> = { ecosystem, name };
  if (typeof version === "string") {
    info.installedVersion = version;
  }
  return info;
}

function isSecretCandidate(file: SourceFile): boolean {
  if (file.kind === "lockfile") {
    return false;
  }
  return file.kind === "source" || file.kind === "config" || file.kind === "text";
}

function isMinifiedJavaScriptAsset(file: SourceFile): boolean {
  return file.baseName.endsWith(".min.js") || file.baseName.endsWith(".min.cjs") || file.baseName.endsWith(".min.mjs");
}

function isConfigCandidate(file: SourceFile): boolean {
  return file.kind === "config" || isDockerfile(file) || isComposeFile(file) || isGitHubWorkflow(file);
}

function isCommittedEnvFile(file: SourceFile): boolean {
  const name = file.baseName.toLowerCase();
  return name.startsWith(".env") && !/(?:example|sample|template|dist|schema)/.test(name);
}

function isDockerfile(file: SourceFile): boolean {
  return file.baseName === "Dockerfile" || file.baseName.startsWith("Dockerfile.");
}

function isComposeFile(file: SourceFile): boolean {
  const name = file.baseName.toLowerCase();
  return name === "docker-compose.yml" || name === "docker-compose.yaml" || name === "compose.yml" || name === "compose.yaml";
}

function isGitHubWorkflow(file: SourceFile): boolean {
  return file.relativePath.startsWith(".github/workflows/") && (file.extension === ".yml" || file.extension === ".yaml");
}

function hasDependencyEntries(packageJson: Record<string, unknown>): boolean {
  return DEPENDENCY_SECTIONS.some((section) => stringEntries(packageJson[section]).length > 0);
}

function hasLockfileForDirectory(manifest: SourceFile, files: SourceFile[], lockfileNames: Set<string>): boolean {
  const manifestDir = path.posix.dirname(manifest.relativePath);
  return files.some((file) => path.posix.dirname(file.relativePath) === manifestDir && lockfileNames.has(file.baseName));
}

function stringEntries(value: unknown): Array<[string, string]> {
  if (!isRecord(value)) {
    return [];
  }
  const result: Array<[string, string]> = [];
  for (const [key, rawValue] of Object.entries(value)) {
    if (typeof rawValue === "string") {
      result.push([key, rawValue]);
    }
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isLikelyPlaceholder(value: string): boolean {
  const normalized = value.toLowerCase();
  return ["example", "sample", "placeholder", "changeme", "change_me", "replace", "redacted", "dummy", "test", "your_", "xxxx", "process.env"].some((marker) => normalized.includes(marker));
}

function isVersionBelow(version: string, floor: string): boolean {
  const left = version.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = floor.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

function compactWhitespace(content: string): string {
  return content.replace(/\s+/g, " ");
}

function linesOf(content: string): Array<{ line: string; number: number }> {
  return content.split(/\r?\n/).map((line, index) => ({ line, number: index + 1 }));
}

function firstLineMatching(content: string, pattern: RegExp): number | undefined {
  for (const { line, number } of linesOf(content)) {
    if (pattern.test(line)) {
      return number;
    }
  }
  return undefined;
}

function lineNumberContaining(content: string, needle: string): number | undefined {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index]?.includes(needle)) {
      return index + 1;
    }
  }
  return undefined;
}

function lineAt(content: string, lineNumber: number): string {
  return content.split(/\r?\n/)[lineNumber - 1] ?? "";
}

function locationFor(file: SourceFile, lineNumber?: number): NonNullable<Finding["location"]> {
  const location: NonNullable<Finding["location"]> = { file: file.relativePath };
  if (lineNumber !== undefined) {
    location.startLine = lineNumber;
  }
  return location;
}

function evidenceFor(file: SourceFile, lineNumber: number | undefined, evidence: string): string {
  const prefix = lineNumber === undefined ? file.relativePath : `${file.relativePath}:${lineNumber}`;
  return `${prefix} ${evidence.trim()}`.trim();
}

function languageFromPath(relativePath: string): SourceFile["language"] {
  const extension = path.extname(relativePath).toLowerCase();
  if (relativePath.includes(".env")) {
    return "text";
  }
  if ([".js", ".jsx", ".mjs", ".cjs"].includes(extension)) {
    return "javascript";
  }
  if ([".ts", ".tsx", ".mts", ".cts"].includes(extension)) {
    return "typescript";
  }
  if (extension === ".py") {
    return "python";
  }
  if (extension === ".java") {
    return "java";
  }
  if (extension === ".jsp") {
    return "jsp";
  }
  if (extension === ".json") {
    return "json";
  }
  if (extension === ".xml") {
    return "xml";
  }
  if (extension === ".yml" || extension === ".yaml") {
    return "yaml";
  }
  if (extension === ".toml") {
    return "toml";
  }
  if (extension === ".properties") {
    return "properties";
  }
  if (extension === ".gradle" || relativePath.endsWith(".gradle.kts")) {
    return "gradle";
  }
  return "text";
}
