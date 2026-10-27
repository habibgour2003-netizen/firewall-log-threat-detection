"""Evaluate source-level synthetic detection outcomes on a fresh holdout set.

Scores are on artificial labels only; they do not estimate production accuracy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.detection import detect_alerts, load_logs


def run_evaluation(input_path: str | Path, truth_path: str | Path, output_path: str | Path) -> dict:
    alerts = detect_alerts(load_logs(input_path))
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    expected = {(r["src_ip"], r["alert_type"]) for r in truth}
    actual = {(r.src_ip, r.alert_type) for r in alerts.itertuples()}
    tp = sorted(expected & actual)
    fp = sorted(actual - expected)
    fn = sorted(expected - actual)
    results = {
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_negatives": len(fn),
        "recall_on_synthetic_cases": round(len(tp) / len(expected), 3) if expected else None,
        "precision_on_synthetic_cases": round(len(tp) / len(actual), 3) if actual else None,
        "detected_cases": [{"src_ip": s, "alert_type": a} for s, a in tp],
        "missed_cases": [{"src_ip": s, "alert_type": a} for s, a in fn],
        "unexpected_alerts": [{"src_ip": s, "alert_type": a} for s, a in fp],
        "disclaimer": "Synthetic scenario-level assessment only; these are not production performance metrics."
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
    return results


def main():
    parser = argparse.ArgumentParser(description="Validate rules on labeled synthetic data")
    parser.add_argument("--input", default="data/validation_firewall_logs.csv")
    parser.add_argument("--truth", default="data/validation_truth.json")
    parser.add_argument("--output", default="outputs/validation/evaluation.json")
    args = parser.parse_args()
    run_evaluation(args.input, args.truth, args.output)


if __name__ == "__main__":
    main()
