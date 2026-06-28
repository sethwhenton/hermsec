#!/usr/bin/env python3
"""Score all modes on ghazal_primary_tests."""
import json
import os
import glob

BASE_DIR = "Test projects/ghazal_primary_tests"
RESULTS_BASE = ".hermsec"

# All modes with their result directories
MODES = {
    "scanner-only": "ghazal-moa-results/moa-low",  # Use scanner-only from benchmark
    "deep-assisted": "ghazal-modes-results/deep-assisted",
    "single-agent": "ghazal-modes-results/single-agent",
    "moa-low": "ghazal-modes-results/moa-low",
    "moa-high": "ghazal-modes-results/moa-high",
    "scanner+moa-low": "ghazal-moa-results/moa-low",
    "scanner+moa-mid": "ghazal-moa-results/moa-mid",
    "scanner+moa-high": "ghazal-moa-results/moa-high",
}

PROJECTS = [
    "nodejs-express-app", "python-flask-app", "java-servlet-app",
    "go-web-app", "php-web-app", "ruby-rails-app", "c-cpp-app",
    "csharp-dotnet-app", "rust-web-app", "advanced-js-ts-app",
    "supply-chain-project", "docker-ci-project", "advanced-java-python"
]

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

def find_findings_json(mode_dir, project):
    pattern = os.path.join(RESULTS_BASE, mode_dir, project, project, "*", "findings.json")
    files = glob.glob(pattern)
    if not files:
        return []
    files.sort()
    with open(files[-1]) as f:
        return json.load(f)

def score_project(project, mode_dir):
    gt_cwes = load_ground_truth(project)
    findings = find_findings_json(mode_dir, project)
    
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
    
    for mode_name, mode_dir in MODES.items():
        mode_results = {"projects": {}, "totals": {"planted": 0, "detected": 0, "tp": 0, "fp": 0, "fn": 0}}
        
        for project in PROJECTS:
            score = score_project(project, mode_dir)
            mode_results["projects"][project] = score
            for key in ["planted", "detected", "tp", "fp", "fn"]:
                mode_results["totals"][key] += score[key]
        
        t = mode_results["totals"]
        t["precision"] = round(t["tp"] / (t["tp"] + t["fp"]), 4) if (t["tp"] + t["fp"]) > 0 else 0
        t["recall"] = round(t["tp"] / (t["tp"] + t["fn"]), 4) if (t["tp"] + t["fn"]) > 0 else 0
        t["f1"] = round(2 * t["precision"] * t["recall"] / (t["precision"] + t["recall"]), 4) if (t["precision"] + t["recall"]) > 0 else 0
        
        results[mode_name] = mode_results
    
    # Print summary table
    print("=" * 100)
    print(f"{'Mode':<20} {'Planted':>8} {'Detected':>10} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    print("=" * 100)
    for mode_name in MODES.keys():
        t = results[mode_name]["totals"]
        print(f"{mode_name:<20} {t['planted']:>8} {t['detected']:>10} {t['tp']:>5} {t['fp']:>5} {t['fn']:>5} {t['precision']:>8.4f} {t['recall']:>8.4f} {t['f1']:>8.4f}")
    print("=" * 100)
    
    # Save results
    with open("all-modes-scoring-results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to all-modes-scoring-results.json")

if __name__ == "__main__":
    main()
