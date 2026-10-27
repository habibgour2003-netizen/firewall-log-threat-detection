"""CSV -> validation -> explainable detections -> SQLite, CSV and JSON reports."""

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from src.detection import detect_alerts, load_logs


def run_pipeline(input_path: str | Path, db_path: str | Path, output_dir: str | Path) -> dict:
    logs = load_logs(input_path)
    alerts = detect_alerts(logs)
    db_path = Path(db_path)
    output_dir = Path(output_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    save_logs = logs.copy()
    save_logs["timestamp"] = save_logs["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    save_alerts = alerts.copy()
    if not save_alerts.empty:
        save_alerts["window_start"] = save_alerts["window_start"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    # sqlite3.Connection context manager commits/rolls back, but does NOT close.
    # On Windows an open handle prevents TemporaryDirectory from deleting result.db.
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            save_logs.to_sql("firewall_logs", conn, if_exists="replace", index=False)
            save_alerts.to_sql("alerts", conn, if_exists="replace", index=False)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_src ON firewall_logs(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_time ON firewall_logs(timestamp)")
    save_alerts.to_csv(output_dir / "alerts.csv", index=False)
    summary = {
        "events": len(logs), "allowed": int((logs["action"] == "ALLOW").sum()),
        "denied": int((logs["action"] == "DENY").sum()),
        "unique_sources": int(logs["src_ip"].nunique()),
        "alerts": len(alerts),
        "alert_counts": {str(k): int(v) for k, v in alerts["alert_type"].value_counts().items()},
        "note": "Detections are heuristic indicators, not confirmed compromises.",
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Defensive firewall log ETL + detection")
    parser.add_argument("--input", default="data/sample_firewall_logs.csv")
    parser.add_argument("--db", default="outputs/firewall_lab.db")
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()
    run_pipeline(args.input, args.db, args.output_dir)


if __name__ == "__main__":
    main()
