#!/usr/bin/env python3
"""Score MoA scan results against ground truth."""
import json
import os
import glob

BASE_DIR = "Test projects/ghazal_primary_tests"
RESULTS_BASE = ".hermsec/ghazal-moa-results"
MODES = ["moa-low", "moa-mid", "moa-high"]
PROJECTS = [
    "nodejs-express-app", "python-flask-app", "java-servlet-app",
    "go-web-app", "php-web-app", "ruby-rails-app", "c-cpp-app",
    "csharp-dotnet-app", "rust-web-app", "advanced-js-ts-app",
    "supply-chain-project", "docker-ci-project", "advanced-java-python"
]

def normalize_cwe(cwe):
    if isinstance(cwe, list):
        return set(normalize_cwe(c) for c in cwe)
    return {cwe.strip() if isinstance(cwe, str) else str(cwe).strip()}

def load_ground_truth(project):
    gt_path = os.path.join(BASE_DIR, project, "ground-truth.json")
    if not os.path.exists(gt_path):
        return set()
    with open(gt_path) as f:
        data = json.load(f)
    cwes = set()
    for v in data.get("vulnerabilities", []):
        cwe = v.get("cwe", "")
        if cwe:
            cwes.add(cwe.strip())
    return cwes

def find_findings_json(mode, project):
    pattern = os.path.join(RESULTS_BASE, mode, project, project, "*", "findings.json")
    files = glob.glob(pattern)
    if not files:
        return []
    files.sort()
    with open(files[-1]) as f:
        return json.load(f)

def score_project(project, mode):
    gt_cwes = load_ground_truth(project)
    findings = find_findings_json(mode, project)
    
    # Extract all CWEs from findings (handle list format)
    finding_cwes = set()
    for f in findings:
        cwe_field = f.get("cwe", "")
        if isinstance(cwe_field, list):
            for c in cwe_field:
                finding_cwes.add(c.strip())
        elif cwe_field:
            finding_cwes.add(cwe_field.strip())
    
    tp = len(finding_cwes & gt_cwes)
    fp = len(finding_cwes - gt_cwes)
    fn = len(gt_cwes - finding_cwes)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "planted": len(gt_cwes),
        "detected": len(finding_cwes),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4)
    }

def main():
    results = {}
    
    for mode in MODES:
        mode_results = {"projects": {}, "totals": {"planted": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0}}
        
        for project in PROJECTS:
            score = score_project(project, mode)
            mode_results["projects"][project] = score
            for key in ["planted", "detected", "tp", "fp", "fn"]:
                mode_results["totals"][key] += score[key]
        
        t = mode_results["totals"]
        t["precision"] = round(t["tp"] / (t["tp"] + t["fp"]), 4) if (t["tp"] + t["fp"]) > 0 else 0
        t["recall"] = round(t["tp"] / (t["tp"] + t["fn"]), 4) if (t["tp"] + t["fn"]) > 0 else 0
        t["f1"] = round(2 * t["precision"] * t["recall"] / (t["precision"] + t["recall"]), 4) if (t["precision"] + t["recall"]) > 0 else 0
        
        results[mode] = mode_results
    
    print("=" * 90)
    print(f"{'Mode':<15} {'Planted':>8} {'Detected':>10} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    print("=" * 90)
    for mode in MODES:
        t = results[mode]["totals"]
        print(f"{mode:<15} {t['planted']:>8} {t['detected']:>10} {t['tp']:>5} {t['fp']:>5} {t['fn']:>5} {t['precision']:>8.4f} {t['recall']:>8.4f} {t['f1']:>8.4f}")
    print("=" * 90)
    
    # Per-project breakdown for best mode
    best_mode = max(MODES, key=lambda m: results[m]["totals"]["f1"])
    print(f"\nPer-project breakdown ({best_mode}):")
    print(f"{'Project':<30} {'Planted':>8} {'TP':>5} {'FP':>5} {'FN':>5} {'F1':>8}")
    print("-" * 70)
    for project in PROJECTS:
        p = results[best_mode]["projects"][project]
        print(f"{project:<30} {p['planted']:>8} {p['tp']:>5} {p['fp']:>5} {p['fn']:>5} {p['f1']:>8.4f}")
    
    with open("ghazal-moa-scoring-results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to ghazal-moa-scoring-results.json")

if __name__ == "__main__":
    main()
