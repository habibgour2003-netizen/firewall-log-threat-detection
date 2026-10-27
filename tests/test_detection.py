import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.detection import detect_alerts, load_logs
from src.generate_sample import build_sample
from src.pipeline import run_pipeline


class TestFirewallThreatLab(unittest.TestCase):
    def test_synthetic_data_detects_both_patterns(self):
        alerts = detect_alerts(load_logs(self._write_csv(build_sample())))
        self.assertIn("POSSIBLE_PORT_SCAN", alerts["alert_type"].tolist())
        self.assertIn("DENY_BURST", alerts["alert_type"].tolist())
        self.assertIn("203.0.113.50", alerts["src_ip"].tolist())
        self.assertIn("198.51.100.23", alerts["src_ip"].tolist())

    def test_allows_only_means_no_alerts(self):
        data = build_sample()
        data["action"] = "ALLOW"
        alerts = detect_alerts(load_logs(self._write_csv(data)))
        self.assertTrue(alerts.empty)

    def test_rejects_invalid_action(self):
        data = build_sample().head(1)
        data.loc[data.index[0], "action"] = "DELETE"
        with self.assertRaisesRegex(ValueError, "action must be"):
            load_logs(self._write_csv(data))

    def test_pipeline_writes_database_and_reports(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            csv_path = path / "test.csv"
            build_sample().to_csv(csv_path, index=False)
            stats = run_pipeline(csv_path, path / "result.db", path / "reports")
            self.assertGreaterEqual(stats["alerts"], 2)
            self.assertTrue((path / "result.db").exists())
            self.assertTrue((path / "reports" / "alerts.csv").exists())
            self.assertTrue((path / "reports" / "summary.json").exists())
            # Windows regression: the database must not remain locked after run_pipeline.
            (path / "result.db").unlink()
            self.assertFalse((path / "result.db").exists())

    def _write_csv(self, frame: pd.DataFrame) -> Path:
        # TemporaryDirectory cleanup deferred until the test finishes.
        if not hasattr(self, "tmp"):
            self.tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "input.csv"
        frame.to_csv(path, index=False)
        return path


if __name__ == "__main__":
    unittest.main()


class TestIndependentValidation(unittest.TestCase):
    """Check expected outcomes on a distinct, labeled synthetic scenario set."""

    def test_validation_scenarios_and_known_miss(self):
        from src.generate_validation import build_validation
        logs = build_validation()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "validation.csv"
            logs.to_csv(path, index=False)
            alerts = detect_alerts(load_logs(path))
            actual = {(row.src_ip, row.alert_type) for row in alerts.itertuples()}
            self.assertEqual(actual, {
                ("203.0.113.70", "POSSIBLE_PORT_SCAN"),
                ("198.51.100.70", "DENY_BURST"),
            })
            self.assertNotIn(("203.0.113.80", "POSSIBLE_PORT_SCAN"), actual)
            self.assertNotIn(("192.0.2.55", "DENY_BURST"), actual)

    def test_evaluation_report(self):
        from src.evaluate import run_evaluation
        from src.generate_validation import TRUTH, build_validation
        import json
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            path = d / "validation.csv"
            truth_path = d / "truth.json"
            build_validation().to_csv(path, index=False)
            truth_path.write_text(json.dumps(TRUTH), encoding="utf-8")
            result = run_evaluation(path, truth_path, d / "evaluation.json")
            self.assertEqual(result["true_positives"], 2)
            self.assertEqual(result["false_positives"], 0)
            self.assertEqual(result["false_negatives"], 1)
            self.assertTrue((d / "evaluation.json").exists())
