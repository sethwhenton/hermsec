import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { walkSourceTree } from "../../../src/core/files.js";
import { scanFile } from "../../../src/scanners/heuristics.js";

const fixturesRoot = path.join(process.cwd(), "tests", "fixtures", "repos");

test("fixture scanner heuristics select expected offline scanner families", () => {
  assert.deepEqual(inferScannerFamilies("node-express-vulnerable"), [
    "gitleaks",
    "npm-audit",
    "osv-scanner",
    "semgrep",
  ]);
  assert.deepEqual(inferScannerFamilies("python-flask-vulnerable"), [
    "bandit",
    "gitleaks",
    "osv-scanner",
    "pip-audit",
    "semgrep",
  ]);
  assert.deepEqual(inferScannerFamilies("node-express-clean"), ["npm-audit", "osv-scanner", "semgrep"]);
  assert.deepEqual(inferScannerFamilies("python-flask-clean"), [
    "bandit",
    "osv-scanner",
    "pip-audit",
    "semgrep",
  ]);
});

test("offline scanner heuristics flag toy vulnerable fixture patterns", () => {
  const nodeSource = fs.readFileSync(
    path.join(fixturesRoot, "node-express-vulnerable", "project", "src", "routes", "search.js"),
    "utf8",
  );
  const findings = scanFile("src/routes/search.js", nodeSource);
  const categories = new Set(findings.map((finding) => finding.category));
  const cwes = new Set(findings.flatMap((finding) => finding.cwe ?? []));

  assert.ok(categories.has("secret"));
  assert.ok(categories.has("code"));
  assert.ok(cwes.has("CWE-78"));
  assert.ok(cwes.has("CWE-89"));
});

test("offline scanner heuristics keep clean fixture noise low", () => {
  const cleanSource = fs.readFileSync(
    path.join(fixturesRoot, "node-express-clean", "project", "src", "routes", "search.js"),
    "utf8",
  );
  const findings = scanFile("src/routes/search.js", cleanSource);
  const highOrCritical = findings.filter((finding) => finding.severity === "high" || finding.severity === "critical");

  assert.deepEqual(highOrCritical, []);
});

test("source walker includes Java and Maven project files", async () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "hermsec-java-fixture-"));
  fs.mkdirSync(path.join(repo, "src", "main", "java"), { recursive: true });
  fs.writeFileSync(path.join(repo, "pom.xml"), "<project></project>\n");
  fs.writeFileSync(path.join(repo, "src", "main", "java", "Example.java"), "class Example {}\n");

  const walk = await walkSourceTree(repo);
  const byName = new Map(walk.files.map((file) => [file.baseName, file]));

  assert.equal(byName.get("pom.xml")?.kind, "manifest");
  assert.equal(byName.get("pom.xml")?.language, "xml");
  assert.equal(byName.get("Example.java")?.kind, "source");
  assert.equal(byName.get("Example.java")?.language, "java");
});

test("offline scanner heuristics flag Java servlet security sinks", () => {
  const findings = scanFile("src/main/java/ExampleServlet.java", `
    import javax.servlet.http.*;
    class ExampleServlet extends HttpServlet {
      void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        String sql = "select * from users where name = '" + param + "'";
        java.sql.Connection connection = null;
        connection.prepareStatement(sql).executeQuery();
        response.getWriter().println("hello " + param);
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.sqli"), true);
  assert.equal(ruleIds.has("hermsec.java.xss"), true);
});

test("Java servlet heuristics track aliases and respect response sanitizers", () => {
  const findings = scanFile("src/main/java/ExampleServlet.java", `
    import javax.servlet.http.*;
    class ExampleServlet extends HttpServlet {
      void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        String bar = param;
        String safe = org.owasp.encoder.Encode.forHtml(bar);
        response.getWriter().println(safe);
        String sql = "select * from users where name = '" + bar + "'";
        java.sql.Connection connection = null;
        connection.prepareStatement(sql).executeQuery();
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.sqli"), true);
  assert.equal(ruleIds.has("hermsec.java.xss"), false);
});

test("Java servlet heuristics do not flag untainted constants at sensitive sinks", () => {
  const findings = scanFile("src/main/java/ExampleServlet.java", `
    import javax.servlet.http.*;
    class ExampleServlet extends HttpServlet {
      void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String sql = "select * from users where active = 1";
        java.sql.Connection connection = null;
        connection.prepareStatement(sql).executeQuery();
        response.getWriter().println("ok");
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.sqli"), false);
  assert.equal(ruleIds.has("hermsec.java.xss"), false);
});

test("Java servlet heuristics track benchmark-style cookie values into file and session sinks", () => {
  const findings = scanFile("src/main/java/BenchmarkTest00001.java", `
    import javax.servlet.http.*;
    class BenchmarkTest00001 extends HttpServlet {
      void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        javax.servlet.http.Cookie[] theCookies = request.getCookies();
        String param = "noCookieValueSupplied";
        if (theCookies != null) {
          for (javax.servlet.http.Cookie theCookie : theCookies) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
          }
        }
        String fileName = "/tmp/" + param;
        new java.io.FileInputStream(new java.io.File(fileName));
        request.getSession().setAttribute(param, "value");
        response.getWriter().println(org.owasp.benchmark.helpers.Utils.encodeForHTML(param));
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.pathtraver"), true);
  assert.equal(ruleIds.has("hermsec.java.trustbound"), true);
  assert.equal(ruleIds.has("hermsec.java.xss"), false);
});

test("Java servlet heuristics track body readers, multipart filenames, and StringBuilder aliases", () => {
  const findings = scanFile("src/main/java/UploadServlet.java", `
    import javax.servlet.http.*;
    import java.io.*;
    class UploadServlet extends HttpServlet {
      void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        BufferedReader reader = request.getReader();
        String body = reader.readLine();
        StringBuilder query = new StringBuilder("select * from audit where body = '");
        query.append(body);
        query.append("'");
        java.sql.Connection connection = null;
        connection.prepareStatement(query.toString()).executeQuery();

        Part part = request.getPart("upload");
        String fileName = part.getSubmittedFileName();
        new FileInputStream(new File("/tmp/" + fileName));
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.sqli"), true);
  assert.equal(ruleIds.has("hermsec.java.pathtraver"), true);
});

test("Java servlet sanitizer families do not hide SQL taint", () => {
  const findings = scanFile("src/main/java/SanitizerServlet.java", `
    import javax.servlet.http.*;
    class SanitizerServlet extends HttpServlet {
      void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("q");
        String safeForHtml = org.owasp.encoder.Encode.forHtml(param);
        response.getWriter().println(safeForHtml);
        String sql = "select * from users where name = '" + safeForHtml + "'";
        java.sql.Connection connection = null;
        connection.prepareStatement(sql).executeQuery();
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.xss"), false);
  assert.equal(ruleIds.has("hermsec.java.sqli"), true);
});

test("Java servlet heuristics detect LDAP and XPath request-taint sinks", () => {
  const findings = scanFile("src/main/java/SearchServlet.java", `
    import javax.servlet.http.*;
    class SearchServlet extends HttpServlet {
      void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filter = request.getHeader("x-user");
        javax.naming.directory.DirContext context = null;
        context.search("ou=people", "(uid=" + filter + ")", null);
        javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        xpath.evaluate("//user[@id='" + filter + "']", new Object());
      }
    }
  `);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("hermsec.java.ldapi"), true);
  assert.equal(ruleIds.has("hermsec.java.xpathi"), true);
});

test("fixture package files do not define package scripts", () => {
  for (const packagePath of listFiles(fixturesRoot).filter((file) => path.basename(file) === "package.json")) {
    const parsed = JSON.parse(fs.readFileSync(packagePath, "utf8")) as { scripts?: unknown };
    assert.equal(parsed.scripts, undefined, `${packagePath} must not define package scripts`);
  }
});

test("fixture manifests enforce local-only fake-secret governance", () => {
  for (const fixtureDir of fs.readdirSync(fixturesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const manifestPath = path.join(fixturesRoot, fixtureDir.name, "hermsec-fixture.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
      fakeSecretsOnly?: boolean;
      safety?: {
        requiresNetwork?: boolean;
        containsExploitCode?: boolean;
        packageScriptsMustNotRun?: boolean;
        allowedTargets?: string[];
      };
    };

    assert.equal(manifest.fakeSecretsOnly, true, `${fixtureDir.name} must allow fake secrets only`);
    assert.equal(manifest.safety?.requiresNetwork, false, `${fixtureDir.name} must not require network`);
    assert.equal(manifest.safety?.containsExploitCode, false, `${fixtureDir.name} must not contain exploit code`);
    assert.equal(
      manifest.safety?.packageScriptsMustNotRun,
      true,
      `${fixtureDir.name} package scripts must not run`,
    );
    assert.deepEqual(manifest.safety?.allowedTargets, ["localhost", "127.0.0.1"]);
  }
});

function inferScannerFamilies(fixtureId: string): string[] {
  const repoPath = path.join(fixturesRoot, fixtureId, "project");
  const files = listFiles(repoPath);
  const relativeFiles = files.map((file) => path.relative(repoPath, file).replace(/\\/g, "/"));
  const text = files.map((file) => fs.readFileSync(file, "utf8")).join("\n");
  const scanners = new Set<string>();

  if (relativeFiles.some((file) => file.endsWith(".js") || file.endsWith(".ts"))) {
    scanners.add("semgrep");
  }

  if (relativeFiles.some((file) => file.endsWith(".py"))) {
    scanners.add("bandit");
    scanners.add("semgrep");
  }

  if (relativeFiles.includes("package-lock.json")) {
    scanners.add("npm-audit");
    scanners.add("osv-scanner");
  }

  if (relativeFiles.includes("requirements.txt")) {
    scanners.add("pip-audit");
    scanners.add("osv-scanner");
  }

  if (text.includes("HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE")) {
    scanners.add("gitleaks");
  }

  return [...scanners].sort();
}

function listFiles(root: string): string[] {
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    return entry.isDirectory() ? listFiles(fullPath) : [fullPath];
  });
}
