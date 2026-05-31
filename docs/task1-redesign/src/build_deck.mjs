import fs from "node:fs";
import path from "node:path";
import JSZip from "file:///C:/Users/whent/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/jszip/lib/index.js";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const W = 1920;
const H = 1080;
const OUT = path.resolve("output");
const SCRATCH = path.resolve("scratch");
const ASSETS = path.resolve("scratch/assets");
const PROJECT = path.resolve("..");
fs.mkdirSync(OUT, { recursive: true });
fs.mkdirSync(SCRATCH, { recursive: true });
fs.mkdirSync(ASSETS, { recursive: true });

const c = {
  bg: "#F8FAFC",
  paper: "#FFFFFF",
  ink: "#0B1220",
  softInk: "#334155",
  muted: "#64748B",
  hair: "#CBD5E1",
  hair2: "#E2E8F0",
  cyan: "#16C8D2",
  cyanDark: "#0A8F99",
  mint: "#D9FBFD",
  slate: "#111827",
  terminal: "#101820",
  amber: "#B7791F",
  red: "#BE123C",
};

const font = {
  display: "Aptos Display",
  body: "Aptos",
  mono: "Cascadia Mono",
};

const images = {
  repos: path.join(PROJECT, "Insider_Lab_II___Task_1/images/repos loaded.png"),
  tokenProgress: path.join(PROJECT, "Insider_Lab_II___Task_1/images/Tokenization Progress Output1.png"),
  models: path.join(PROJECT, "Insider_Lab_II___Task_1/images/All 17 Model Files Sorted by Size.png"),
  verify: path.join(PROJECT, "Insider_Lab_II___Task_1/images/Model Verification (MOST IMPORTANT).png"),
};

const presentation = Presentation.create({
  slideSize: { width: W, height: H },
});

function slide() {
  const s = presentation.slides.add();
  rect(s, 0, 0, W, H, c.bg, null, "background");
  topMark(s);
  return s;
}

function rect(s, x, y, w, h, fill = c.paper, line = c.hair, name = undefined, radius = "rect") {
  const shape = s.shapes.add({
    geometry: radius,
    position: { left: x, top: y, width: w, height: h },
    fill: fill ? { type: "solid", color: fill } : undefined,
    line: line ? { style: "solid", fill: line, width: 1 } : { width: 0 },
  });
  if (name) shape.name = name;
  return shape;
}

function line(s, x, y, w, h = 2, color = c.hair, name = undefined) {
  return rect(s, x, y, w, h, color, null, name);
}

function textBox(s, value, x, y, w, h, opts = {}) {
  const shape = rect(s, x, y, w, h, opts.fill ?? c.bg, opts.line ?? null, opts.name);
  shape.text.style = {
    fontSize: opts.size ?? 28,
    color: opts.color ?? c.ink,
    bold: opts.bold ?? false,
    italic: opts.italic ?? false,
    typeface: opts.font ?? font.body,
    alignment: opts.align ?? "left",
    verticalAlignment: opts.valign ?? "top",
  };
  shape.text = value;
  return shape;
}

function eyebrow(s, value, x = 112, y = 64, w = 900) {
  return textBox(s, value.toUpperCase(), x, y, w, 38, {
    size: 17,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
    name: "eyebrow",
  });
}

function title(s, value, x = 112, y = 132, w = 1380, h = 150, size = 62) {
  return textBox(s, value, x, y, w, h, {
    size,
    color: c.ink,
    bold: true,
    font: font.display,
    name: "slide-title",
  });
}

function subtitle(s, value, x = 116, y = 276, w = 1160, h = 86, size = 28) {
  return textBox(s, value, x, y, w, h, {
    size,
    color: c.softInk,
    font: font.body,
    name: "subtitle",
  });
}

function topMark(s) {
  line(s, 112, 42, 94, 5, c.cyan);
  line(s, 216, 42, 24, 5, c.ink);
  textBox(s, "SECURITY INSIDER LAB II", 1530, 48, 280, 30, {
    size: 14,
    color: c.muted,
    align: "right",
    font: font.mono,
    name: "section-mark",
  });
}

function foot(s, n) {
  textBox(s, String(n).padStart(2, "0"), 1772, 1000, 44, 26, {
    size: 13,
    color: c.muted,
    font: font.mono,
    align: "right",
    name: "page-number",
  });
}

function imageFrame(s, img, x, y, w, h, opts = {}) {
  const bg = rect(s, x, y, w, h, opts.fill ?? c.paper, opts.line ?? c.hair2, opts.name ? `${opts.name}-frame` : undefined, "roundRect");
  const pad = opts.pad ?? 14;
  const dataUrl = `data:image/png;base64,${fs.readFileSync(img).toString("base64")}`;
  s.images.add({
    dataUrl,
    alt: opts.alt ?? "Evidence screenshot",
    position: { left: x + pad, top: y + pad, width: w - 2 * pad, height: h - 2 * pad },
    fit: opts.fit ?? "contain",
  });
  return bg;
}

function metric(s, value, label, x, y, w, accent = c.cyan) {
  textBox(s, value, x, y, w, 86, {
    size: 70,
    color: c.ink,
    bold: true,
    font: font.display,
    name: `metric-${label}`,
  });
  line(s, x, y + 92, 120, 4, accent);
  textBox(s, label, x, y + 112, w, 62, {
    size: 22,
    color: c.muted,
    font: font.body,
  });
}

function bullet(s, text, x, y, w, opts = {}) {
  line(s, x, y + 16, 24, 3, opts.accent ?? c.cyan);
  textBox(s, text, x + 42, y, w - 42, opts.h ?? 54, {
    size: opts.size ?? 25,
    color: opts.color ?? c.softInk,
    bold: opts.bold ?? false,
    font: opts.font ?? font.body,
  });
}

function terminalLine(s, text, x, y, w, opts = {}) {
  textBox(s, text, x, y, w, opts.h ?? 42, {
    size: opts.size ?? 23,
    color: opts.color ?? c.cyan,
    font: font.mono,
    fill: opts.fill ?? c.terminal,
    name: opts.name,
  });
}

function addCover() {
  const s = presentation.slides.add();
  rect(s, 0, 0, W, H, c.bg, null, "background");
  line(s, 112, 78, 124, 6, c.cyan);
  textBox(s, "GROUP G4 / UNIVERSITY OF PASSAU", 112, 116, 720, 40, {
    size: 18,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
  });
  textBox(s, "ML-based\nPython Source Code\nVulnerabilities", 112, 238, 1100, 330, {
    size: 80,
    color: c.ink,
    bold: true,
    font: font.display,
    name: "cover-title",
  });
  textBox(s, "Security Insider Lab II / Task 1", 118, 612, 760, 46, {
    size: 30,
    color: c.softInk,
    font: font.body,
    name: "cover-subtitle",
  });
  textBox(s, "Ghazal Pouresfandiyar Borojeni\nSeth Whenton\n29.04.2026", 118, 704, 620, 112, {
    size: 24,
    color: c.muted,
    font: font.body,
  });

  rect(s, 1160, 220, 560, 500, c.paper, c.hair2, "cover-terminal", "roundRect");
  rect(s, 1190, 250, 500, 70, c.terminal, null, "terminal-top", "roundRect");
  terminalLine(s, "> train word2vec --corpus python", 1224, 268, 450, { size: 20, name: "terminal-command" });
  textBox(s, "SEC", 1210, 380, 230, 110, {
    size: 94,
    color: c.ink,
    bold: true,
    font: font.mono,
    fill: c.paper,
  });
  textBox(s, "TOKENS", 1216, 512, 280, 48, {
    size: 22,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
    fill: c.paper,
  });
  line(s, 1216, 584, 420, 3, c.hair);
  line(s, 1216, 622, 310, 3, c.hair2);
  line(s, 1216, 660, 360, 3, c.hair2);
  rect(s, 1580, 380, 80, 80, c.mint, c.cyan, "cover-cube", "roundRect");
  textBox(s, "17", 1580, 388, 80, 60, {
    size: 34,
    color: c.cyanDark,
    bold: true,
    align: "center",
    valign: "middle",
    font: font.display,
    fill: c.mint,
  });
  textBox(s, "models", 1550, 470, 140, 30, {
    size: 18,
    color: c.muted,
    align: "center",
    font: font.mono,
    fill: c.paper,
  });
  line(s, 112, 968, 1420, 1, c.hair2);
  textBox(s, "White-mode terminal aesthetic / clean evidence / minimal live-read slides", 112, 992, 900, 32, {
    size: 16,
    color: c.muted,
    font: font.mono,
  });
}

function addObjective() {
  const s = slide();
  eyebrow(s, "What this deck proves");
  title(s, "Security knowledge becomes a code-embedding pipeline");
  subtitle(s, "Task 1 connects vulnerability patterns with a practical Word2Vec workflow for Python source code.");
  metric(s, "7", "web vulnerability classes documented", 156, 455, 420);
  metric(s, "5", "pipeline stages from corpus to model", 730, 455, 440);
  metric(s, "17", "Word2Vec model files delivered", 1290, 455, 420);
  line(s, 112, 830, 1510, 1, c.hair2);
  textBox(s, "The model is not a detector yet. It creates token vectors that can support later vulnerability classifiers.", 156, 878, 1280, 72, {
    size: 30,
    color: c.ink,
    bold: true,
    font: font.display,
  });
  foot(s, 2);
}

function addVulnerabilities() {
  const s = slide();
  eyebrow(s, "Exercise 1");
  title(s, "Most web vulnerabilities start at a trust boundary");
  subtitle(s, "The seven required classes were grouped by how attacker-controlled input moves through the system.");

  const groups = [
    ["Injection", "SQL Injection\nCommand Injection"],
    ["Client side", "XSS\nCSRF / XSRF"],
    ["Information & access", "Path Disclosure\nOpen Redirect"],
    ["Critical impact", "Remote Code Execution"],
  ];
  const x0 = 152;
  const y0 = 438;
  const gap = 64;
  const bw = 360;
  groups.forEach(([head, body], i) => {
    const x = x0 + i * (bw + gap);
    line(s, x, y0, bw, 4, i === 3 ? c.red : c.cyan);
    textBox(s, head, x, y0 + 34, bw, 40, {
      size: 20,
      color: i === 3 ? c.red : c.cyanDark,
      bold: true,
      font: font.mono,
    });
    textBox(s, body, x, y0 + 94, bw, 132, {
      size: 31,
      color: c.ink,
      bold: true,
      font: font.display,
    });
  });
  line(s, 152, 748, 1464, 1, c.hair2);
  textBox(s, "Prevention pattern: validate input, encode output, avoid unsafe execution, and reveal less internal detail.", 152, 800, 1288, 68, {
    size: 32,
    color: c.softInk,
    font: font.body,
  });
  foot(s, 3);
}

function addPipeline() {
  const s = slide();
  eyebrow(s, "Exercise 2");
  title(s, "The lab pipeline turns raw repositories into trainable token sequences");
  subtitle(s, "Each stage had a concrete output and a compatibility repair before the models could be trained.");

  const steps = [
    ["01", "Corpus", "8 GitHub repositories\n165 MB Python source"],
    ["02", "Clean", "UTF-8 handling\nPython 3 syntax repair"],
    ["03", "Tokenize", "34.6M tokens\n35 part files"],
    ["04", "Merge", "124 MB training file\nwithString mode"],
    ["05", "Train", "16 new configs\nrequired model included"],
  ];
  const x = 154;
  const y = 482;
  const stepW = 294;
  steps.forEach(([num, head, body], i) => {
    const left = x + i * stepW;
    textBox(s, num, left, y, 82, 58, {
      size: 26,
      color: c.cyanDark,
      bold: true,
      font: font.mono,
      align: "center",
      valign: "middle",
    });
    line(s, left + 100, y + 28, i === steps.length - 1 ? 150 : 190, 2, c.hair);
    textBox(s, head, left, y + 108, 250, 46, {
      size: 34,
      color: c.ink,
      bold: true,
      font: font.display,
    });
    textBox(s, body, left, y + 166, 260, 90, {
      size: 21,
      color: c.muted,
      font: font.body,
    });
  });
  terminalLine(s, "> output: word2vec_withString10-200-300.model", 154, 868, 760, { size: 22 });
  foot(s, 4);
}

function addCorpus() {
  const s = slide();
  eyebrow(s, "Corpus creation and cleaning");
  title(s, "The dataset came from major Python projects, then had to be normalized");
  metric(s, "165 MB", "raw and cleaned Python corpus", 154, 404, 500);
  metric(s, "8", "repositories mined with pydriller", 154, 640, 500);
  textBox(s, "Django / NumPy / TensorFlow / Scikit-learn / Flask / SciPy / sqlmap / Docker Compose", 154, 836, 670, 78, {
    size: 25,
    color: c.softInk,
    font: font.body,
  });
  imageFrame(s, images.repos, 940, 350, 760, 430, {
    alt: "Terminal output showing repositories loaded during corpus creation",
    name: "repos-proof",
    pad: 16,
  });
  textBox(s, "Compatibility fixes: pydriller API update, UTF-8 file handling, and safer per-repository error handling.", 944, 820, 720, 62, {
    size: 23,
    color: c.muted,
    font: font.body,
  });
  foot(s, 5);
}

function addTokenization() {
  const s = slide();
  eyebrow(s, "Tokenizer rewrite");
  title(s, "The tokenizer stopped crashing once broken snippets were isolated");
  subtitle(s, "The raw corpus is many files joined together, not one valid Python program, so the tokenizer had to fail softly.");
  metric(s, "34.6M", "tokens processed", 152, 454, 380);
  metric(s, "678k", "snippets attempted", 570, 454, 360);
  metric(s, "85.9k", "bad snippets skipped", 960, 454, 360, c.amber);
  textBox(s, "Old behavior: one indentation error could stop the whole run.\nNew behavior: tokenize each snippet, catch errors, keep the usable corpus.", 152, 730, 980, 112, {
    size: 31,
    color: c.ink,
    bold: true,
    font: font.display,
  });
  terminalLine(s, "> Python tokenize.tokenize(f.readline)  +  per-snippet try/except", 152, 896, 1060, { size: 20 });
  imageFrame(s, images.tokenProgress, 1376, 360, 370, 510, {
    alt: "Tokenization progress terminal output",
    name: "token-progress-proof",
    pad: 12,
  });
  foot(s, 6);
}

function addTraining() {
  const s = slide();
  eyebrow(s, "Model training");
  title(s, "A targeted training matrix replaced an unrealistic 378-combination run");
  subtitle(s, "The selected models varied min_count, epochs, and vector_size while preserving the required configuration.");

  const params = [
    ["min_count", "10 / 30 / 50 / 100", "controls vocabulary size"],
    ["epochs", "50 / 100 / 200", "controls training passes"],
    ["vector_size", "5 to 300", "controls embedding detail"],
  ];
  params.forEach(([head, val, note], i) => {
    const x = 180 + i * 520;
    line(s, x, 456, 300, 4, c.cyan);
    textBox(s, head, x, 492, 320, 42, {
      size: 24,
      color: c.cyanDark,
      bold: true,
      font: font.mono,
    });
    textBox(s, val, x, 554, 360, 58, {
      size: 36,
      color: c.ink,
      bold: true,
      font: font.display,
    });
    textBox(s, note, x, 626, 360, 56, {
      size: 22,
      color: c.muted,
      font: font.body,
    });
  });
  rect(s, 340, 796, 1230, 90, c.terminal, null, "required-model-strip", "roundRect");
  terminalLine(s, "> required: min_count=10  epochs=200  vector_size=300", 386, 820, 1100, { size: 27, name: "required-model" });
  textBox(s, "Training ran on a Hetzner Ubuntu VPS; a 4 GB swap file was added after an out-of-memory kill.", 354, 910, 1200, 52, {
    size: 24,
    color: c.softInk,
    align: "center",
    font: font.body,
  });
  foot(s, 7);
}

function addResults() {
  const s = slide();
  eyebrow(s, "Results");
  title(s, "The submission package contains the required model and more than 15 total models");
  metric(s, "17", "model files present", 154, 384, 390);
  metric(s, "597 MB", "final model archive", 154, 612, 420);
  metric(s, "~152 MB", "real size of required model with .npy vectors", 154, 828, 570);
  imageFrame(s, images.models, 886, 318, 840, 558, {
    alt: "Directory listing of all 17 Word2Vec model files sorted by size",
    name: "models-proof",
    pad: 14,
  });
  textBox(s, "The small .model file is only metadata; the trained vector arrays live in companion .npy files.", 894, 912, 780, 52, {
    size: 23,
    color: c.muted,
    font: font.body,
  });
  foot(s, 8);
}

function addVerification() {
  const s = slide();
  eyebrow(s, "Verification");
  title(s, "The required model learned meaningful Python control-flow relationships");
  subtitle(s, "A simple similarity probe checked whether the embedding space made intuitive sense.");
  textBox(s, "most_similar(\"if\")", 160, 412, 580, 54, {
    size: 34,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
  });
  textBox(s, "elif", 160, 496, 360, 112, {
    size: 96,
    color: c.ink,
    bold: true,
    font: font.display,
  });
  textBox(s, "0.7564 similarity", 168, 626, 410, 42, {
    size: 26,
    color: c.muted,
    font: font.mono,
  });
  bullet(s, "Other nearby tokens included assert, while, raise, else, and break.", 160, 752, 680, { size: 25 });
  bullet(s, "This validates the embedding pipeline, not a finished vulnerability detector.", 160, 824, 720, { size: 25, accent: c.amber });
  rect(s, 960, 366, 720, 420, c.terminal, null, "verification-terminal", "roundRect");
  terminalLine(s, "$ verify word2vec_withString10-200-300.model", 1000, 406, 660, { size: 20 });
  textBox(s, "nearest tokens", 1000, 474, 260, 34, {
    size: 18,
    color: c.cyan,
    bold: true,
    font: font.mono,
    fill: c.terminal,
  });
  const rows = [
    ["elif", "0.7564"],
    ["assert", "0.5855"],
    ["while", "0.5106"],
    ["raise", "0.3777"],
    ["else", "0.3692"],
  ];
  rows.forEach(([tok, score], i) => {
    const y = 532 + i * 38;
    textBox(s, tok, 1000, y, 240, 30, {
      size: i === 0 ? 24 : 20,
      color: i === 0 ? c.cyan : "#D6E3EA",
      bold: i === 0,
      font: font.mono,
      fill: c.terminal,
    });
    textBox(s, score, 1400, y, 180, 30, {
      size: i === 0 ? 24 : 20,
      color: i === 0 ? c.cyan : "#D6E3EA",
      bold: i === 0,
      font: font.mono,
      fill: c.terminal,
      align: "right",
    });
  });
  line(s, 1000, 724, 596, 1, "#27424E");
  textBox(s, "Control-flow tokens cluster together.", 1000, 744, 600, 34, {
    size: 19,
    color: "#D6E3EA",
    font: font.mono,
    fill: c.terminal,
  });
  foot(s, 9);
}

function addLessons() {
  const s = slide();
  eyebrow(s, "Lessons learned");
  title(s, "The hardest work was modernizing the old pipeline, not calling Word2Vec");
  subtitle(s, "The fixes are also the story: every failure mode became a more robust data-preparation step.");

  const rows = [
    ["API drift", "pydriller and gensim calls changed"],
    ["Encoding", "Windows defaults could not read every corpus character"],
    ["Tokenizer crashes", "bad indentation had to be skipped locally"],
    ["Hardware limits", "VPS memory needed swap before training could finish"],
  ];
  rows.forEach(([head, body], i) => {
    const y = 410 + i * 118;
    textBox(s, head, 170, y, 300, 38, {
      size: 25,
      color: c.cyanDark,
      bold: true,
      font: font.mono,
    });
    line(s, 494, y + 18, 78, 2, c.hair);
    textBox(s, body, 610, y - 6, 920, 56, {
      size: 32,
      color: c.ink,
      bold: true,
      font: font.display,
    });
  });
  line(s, 170, 900, 1260, 1, c.hair2);
  textBox(s, "Security part: know the dangerous patterns. ML part: represent code tokens so a future detector can learn those patterns.", 170, 936, 1260, 58, {
    size: 25,
    color: c.softInk,
    font: font.body,
  });
  foot(s, 10);
}

function addHermSecConcept() {
  const s = slide();
  rect(s, 0, 0, W, H, c.bg, null, "background");
  line(s, 112, 78, 124, 6, c.cyan);
  textBox(s, "LAB 5 PROJECT IDEA", 112, 116, 720, 40, {
    size: 18,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
  });
  textBox(s, "HERMSEC", 112, 258, 820, 142, {
    size: 122,
    color: c.ink,
    bold: true,
    font: font.mono,
    name: "hermsec-wordmark",
  });
  line(s, 118, 414, 690, 6, c.cyan);
  textBox(s, "A CVE-aware AI security agent for repositories", 118, 462, 850, 62, {
    size: 34,
    color: c.softInk,
    font: font.body,
  });
  rect(s, 1108, 214, 590, 444, c.paper, c.hair2, "white-terminal", "roundRect");
  rect(s, 1144, 250, 518, 84, c.terminal, null, "terminal-header", "roundRect");
  terminalLine(s, "> scan https://github.com/org/repo", 1180, 276, 440, { size: 22 });
  const terminalRows = [
    "[1/5] Reading repository structure",
    "[2/5] Running Bandit and Semgrep",
    "[3/5] Checking dependency CVEs",
    "[4/5] Asking selected model to explain",
    "[5/5] Writing Markdown report",
  ];
  terminalRows.forEach((row, i) => {
    textBox(s, row, 1174, 376 + i * 48, 470, 34, {
      size: 19,
      color: i === 4 ? c.cyanDark : c.softInk,
      font: font.mono,
      fill: c.paper,
    });
  });
  bullet(s, "Bring-your-own-model: OpenRouter, Ollama, LM Studio, or another compatible API.", 118, 650, 820);
  bullet(s, "Scanners and CVE databases produce evidence; the model explains and prioritizes it.", 118, 724, 880);
  bullet(s, "The tool stays defensive: scan, explain, suggest fixes, and avoid inventing CVEs.", 118, 798, 850, { accent: c.amber });
  foot(s, 11);
}

function addHermSecWorkflow() {
  const s = slide();
  eyebrow(s, "HermesSec workflow");
  title(s, "Repository evidence flows through scanners before the model explains it");
  subtitle(s, "The AI layer is useful because it translates confirmed scanner output into developer-friendly action.");

  const nodes = [
    ["GitHub URL\nor local path", 132, 458, 300],
    ["Bandit\nSemgrep", 522, 458, 260],
    ["pip-audit\nOSV-Scanner", 860, 458, 300],
    ["BYOM AI\nexplanation", 1254, 458, 260],
    ["Security report\nseverity / CVE / fix", 1560, 458, 270],
  ];
  nodes.forEach(([label, x, y, w], i) => {
    line(s, x, y - 34, w, 4, i === 4 ? c.cyan : c.hair);
    textBox(s, label, x, y, w, 104, {
      size: 28,
      color: c.ink,
      bold: true,
      font: font.display,
      align: "center",
      valign: "middle",
    });
    if (i < nodes.length - 1) {
      line(s, x + w + 22, y + 50, 96, 2, c.hair);
      rect(s, x + w + 112, y + 42, 16, 16, c.cyan, null, `flow-dot-${i}`, "ellipse");
    }
  });
  line(s, 132, 710, 1588, 1, c.hair2);
  textBox(s, "Suggested demo command", 132, 760, 430, 34, {
    size: 20,
    color: c.cyanDark,
    bold: true,
    font: font.mono,
  });
  rect(s, 132, 810, 780, 82, c.terminal, null, "demo-command-strip", "roundRect");
  terminalLine(s, "> hermsec scan ./examples/vulnerable-python-app", 170, 834, 700, { size: 23 });
  textBox(s, "Questions?", 1280, 790, 420, 72, {
    size: 56,
    color: c.ink,
    bold: true,
    font: font.display,
    align: "right",
  });
  textBox(s, "Group G4 / Security Insider Lab II", 1260, 870, 440, 32, {
    size: 18,
    color: c.muted,
    font: font.mono,
    align: "right",
  });
  foot(s, 12);
}

addCover();
addObjective();
addVulnerabilities();
addPipeline();
addCorpus();
addTokenization();
addTraining();
addResults();
addVerification();
addLessons();
addHermSecConcept();
addHermSecWorkflow();

const pptxPath = path.join(OUT, "HermSec_Task1_Redesign.pptx");
const sourcePreviewDir = path.join(SCRATCH, "previews-source");
const pptxPreviewDir = path.join(SCRATCH, "previews-pptx");
fs.mkdirSync(sourcePreviewDir, { recursive: true });
fs.mkdirSync(pptxPreviewDir, { recursive: true });

async function saveBlob(blob, file) {
  const bytes = Buffer.from(await blob.arrayBuffer());
  fs.writeFileSync(file, bytes);
}

async function exportPreviews(deck, dir) {
  for (let i = 0; i < deck.slides.count; i += 1) {
    const s = deck.slides.getItem(i);
    const blob = await s.export({ format: "png", scale: 1 });
    await saveBlob(blob, path.join(dir, `slide-${String(i + 1).padStart(2, "0")}.png`));
  }
}

await exportPreviews(presentation, sourcePreviewDir);
const pptxBlob = await PresentationFile.exportPptx(presentation);
await pptxBlob.save(pptxPath);

const pptxBytes = fs.readFileSync(pptxPath);
const reloaded = await PresentationFile.importPptx(new Uint8Array(pptxBytes));
await exportPreviews(reloaded, pptxPreviewDir);

const zip = await JSZip.loadAsync(pptxBytes);
const xmlEntries = Object.keys(zip.files).filter((name) => /^ppt\/slides\/slide\d+\.xml$/.test(name));
let placeholderHits = [];
for (const name of xmlEntries) {
  const xml = await zip.files[name].async("string");
  if (/sldNum|Slide Number|Click to add/i.test(xml)) placeholderHits.push(name);
}

const report = {
  slides: presentation.slides.count,
  pptx: pptxPath,
  source_previews: sourcePreviewDir,
  pptx_previews: pptxPreviewDir,
  placeholder_hits: placeholderHits,
  source_preview_count: fs.readdirSync(sourcePreviewDir).filter((x) => x.endsWith(".png")).length,
  pptx_preview_count: fs.readdirSync(pptxPreviewDir).filter((x) => x.endsWith(".png")).length,
};
fs.writeFileSync(path.join(SCRATCH, "qa-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
console.log(JSON.stringify(report, null, 2));
