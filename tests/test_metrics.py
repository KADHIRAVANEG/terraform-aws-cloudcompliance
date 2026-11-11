import json
import tempfile
import unittest
from pathlib import Path

from cloudcompliance.metrics import generate_prometheus_metrics


class TestMetrics(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.comp_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_metrics_fallback_empty_directory(self):
        metrics_text = generate_prometheus_metrics(self.comp_dir)
        self.assertIn("cloudcompliance_score{framework=\"soc2\"} 0", metrics_text)
        self.assertIn("cloudcompliance_drift_count 0", metrics_text)
        self.assertIn("cloudcompliance_remediation_auto_fixed_total 0", metrics_text)

    def test_metrics_populated_state(self):
        soc2_file = self.comp_dir / "soc2_compliance_report.json"
        with open(soc2_file, "w") as f:
            json.dump({
                "compliance_score": 100,
                "total_resources": 42,
                "controls": {
                    "CC6.1": {"status": "PASS"},
                    "CC6.2": {"status": "PASS"},
                },
                "generated_at": "2026-11-11T12:00:00"
            }, f)

        hipaa_file = self.comp_dir / "hipaa_compliance_report.json"
        with open(hipaa_file, "w") as f:
            json.dump({
                "compliance_score": 80,
                "total_resources": 42,
                "controls": {
                    "164.312(a)(1)": {"status": "PASS"},
                    "164.312(b)": {"status": "FAIL"},
                },
                "generated_at": "2026-11-11T12:00:00"
            }, f)

        drift_file = self.comp_dir / "drift_report.json"
        with open(drift_file, "w") as f:
            json.dump({"drift_count": 3}, f)

        remed_file = self.comp_dir / "remediation_log.json"
        with open(remed_file, "w") as f:
            json.dump({"auto_fixed": 4, "prs_opened": 2}, f)

        metrics_text = generate_prometheus_metrics(self.comp_dir)

        # Assertions
        self.assertIn("cloudcompliance_score{framework=\"soc2\"} 100", metrics_text)
        self.assertIn("cloudcompliance_score{framework=\"hipaa\"} 80", metrics_text)
        self.assertIn("cloudcompliance_controls_passing{framework=\"soc2\"} 2", metrics_text)
        self.assertIn("cloudcompliance_controls_total{framework=\"soc2\"} 2", metrics_text)
        self.assertIn("cloudcompliance_controls_passing{framework=\"hipaa\"} 1", metrics_text)
        self.assertIn("cloudcompliance_controls_total{framework=\"hipaa\"} 2", metrics_text)
        self.assertIn("cloudcompliance_drift_count 3", metrics_text)
        self.assertIn("cloudcompliance_remediation_auto_fixed_total 4", metrics_text)
        self.assertIn("cloudcompliance_remediation_prs_opened_total 2", metrics_text)


if __name__ == "__main__":
    unittest.main()
