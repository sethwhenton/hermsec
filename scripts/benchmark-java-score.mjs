#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const CATEGORY_BY_RULE = new Map([
  ["hermsec.java.cmdi", "cmdi"],
  ["hermsec.java.crypto", "crypto"],
  ["hermsec.java.hash", "hash"],
  ["hermsec.java.ldapi", "ldapi"],
  ["hermsec.java.pathtraver", "pathtraver"],
  ["hermsec.java.securecookie", "securecookie"],
  ["hermsec.java.sqli", "sqli"],
  ["hermsec.java.trustbound", "trustbound"],
  ["hermsec.java.weakrand", "weakrand"],
  ["hermsec.java.xpathi", "xpathi"],
  ["hermsec.java.xss", "xss"],
  ["hermsec.java-process-exec", "cmdi"],
  ["hermsec.java-sql-dynamic", "sqli"],
  ["hermsec.java-xss-writer", "xss"],
]);

const CATEGORY_BY_CWE = new Map([
  ["CWE-22", "pathtraver"],
  ["CWE-78", "cmdi"],
  ["CWE-79", "xss"],
  ["CWE-89", "sqli"],
  ["CWE-90", "ldapi"],
  ["CWE-327", "crypto"],
  ["CWE-328", "hash"],
  ["CWE-330", "weakrand"],
  ["CWE-501", "trustbound"],
  ["CWE-614", "securecookie"],
  ["CWE-643", "xpathi"],
]);

const [expectedPath, scanPath] = process.argv.slice(2);
if (!expectedPath || !scanPath) {
  console.error("Usage: node scripts/benchmark-java-score.mjs <expectedresults-1.2.csv> <hermsec-scan-result.json>");
  process.exit(2);
}

const expected = readExpected(expectedPath);
const scan = readJson(scanPath);
const findings = Array.isArray(scan.findings)
  ? scan.findings
  : Array.isArray(scan.data?.scan?.findings)
    ? scan.data.scan.findings
    : [];
const predicted = predictionsFromFindings(findings);
const result = score(expected, predicted, findings);
console.log(`${JSON.stringify(result, null, 2)}\n`);

function readExpected(filePath) {
  const lines = fs.readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  return lines.map((line) => {
    const [test, category, real, cwe] = line.split(",");
    return {
      test,
      category,
      vulnerable: real === "true",
      cwe,
    };
  });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
}

function predictionsFromFindings(findings) {
  const predictions = new Set();
  const ignored = [];
  for (const finding of findings) {
    const file = String(finding?.location?.file ?? finding?.evidence ?? "");
    const test = /BenchmarkTest\d+/.exec(file)?.[0];
    const category = categoryForFinding(finding);
    if (!test || !category) {
      if (test) {
        ignored.push({
          test,
          ruleId: finding?.ruleId,
          title: finding?.title,
        });
      }
      continue;
    }
    predictions.add(`${test}:${category}`);
  }
  return { predictions, ignored };
}

function categoryForFinding(finding) {
  const ruleId = typeof finding?.ruleId === "string" ? finding.ruleId : "";
  if (CATEGORY_BY_RULE.has(ruleId)) {
    return CATEGORY_BY_RULE.get(ruleId);
  }
  const javaRule = /^hermsec\.java\.([a-z]+)$/.exec(ruleId);
  if (javaRule && CATEGORY_BY_RULE.has(`hermsec.java.${javaRule[1]}`)) {
    return javaRule[1];
  }
  for (const cwe of Array.isArray(finding?.cwe) ? finding.cwe : []) {
    if (CATEGORY_BY_CWE.has(cwe)) {
      return CATEGORY_BY_CWE.get(cwe);
    }
  }
  return undefined;
}

function score(expected, predicted, findings) {
  const categories = new Map();
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;

  for (const row of expected) {
    const category = ensureCategory(categories, row.category);
    const hit = predicted.predictions.has(`${row.test}:${row.category}`);
    category.total += 1;
    if (row.vulnerable) {
      category.vulnerable += 1;
    } else {
      category.safe += 1;
    }
    if (hit) {
      category.predicted += 1;
    }

    if (hit && row.vulnerable) {
      tp += 1;
      category.tp += 1;
    } else if (hit && !row.vulnerable) {
      fp += 1;
      category.fp += 1;
    } else if (!hit && row.vulnerable) {
      fn += 1;
      category.fn += 1;
    } else {
      tn += 1;
      category.tn += 1;
    }
  }

  const extraPredictions = [...predicted.predictions].filter((prediction) => {
    const [test, category] = prediction.split(":");
    return !expected.some((row) => row.test === test && row.category === category);
  });

  return {
    suite: {
      expected: path.basename(expectedPath),
      scan: path.basename(scanPath),
      totalTests: expected.length,
      vulnerableTests: expected.filter((row) => row.vulnerable).length,
      safeTests: expected.filter((row) => !row.vulnerable).length,
    },
    scan: {
      findings: findings.length,
      benchmarkPredictions: predicted.predictions.size,
      ignoredBenchmarkFindings: predicted.ignored.length,
      extraPredictions: extraPredictions.length,
    },
    metrics: metrics({ tp, fp, fn, tn }),
    categories: Object.fromEntries(
      [...categories.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, counts]) => [name, { ...counts, ...rates(counts) }]),
    ),
    ignoredBenchmarkFindings: predicted.ignored.slice(0, 25),
  };
}

function ensureCategory(categories, name) {
  if (!categories.has(name)) {
    categories.set(name, {
      total: 0,
      vulnerable: 0,
      safe: 0,
      predicted: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      tn: 0,
    });
  }
  return categories.get(name);
}

function metrics(counts) {
  return {
    ...counts,
    ...rates(counts),
  };
}

function rates({ tp, fp, fn, tn }) {
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  const falsePositiveRate = divide(fp, fp + tn);
  const accuracy = divide(tp + tn, tp + fp + fn + tn);
  const f1 = divide(2 * precision * recall, precision + recall);
  return {
    precision,
    recall,
    falsePositiveRate,
    accuracy,
    f1,
  };
}

function divide(numerator, denominator) {
  return denominator === 0 ? 0 : Number((numerator / denominator).toFixed(4));
}
