import json
import tempfile
import unittest
from pathlib import Path

from cloudcompliance.sarif import generate_sarif, save_sarif


class TestSarifExport(unittest.TestCase):
    def setUp(self):
        self.sample_results = {
            "CC6.1": {
                "title": "Logical and physical access controls",
                "description": "Ensure encryption and access control",
                "status": "PASS",
                "matched": ["aws_kms_key.key"],
                "missing": [],
            },
            "CC6.6": {
                "title": "Boundary protection",
                "description": "Ensure VPC flow logs and boundaries",
                "status": "FAIL",
                "matched": [],
                "missing": ["aws_flow_log"],
            },
        }

    def test_generate_sarif_structure(self):
        sarif = generate_sarif(self.sample_results, framework="soc2")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CloudCompliance")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)

        # Only non-PASS controls generate findings in results
        results = run["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "SOC2-CC6.6")
        self.assertEqual(results[0]["level"], "error")
        self.assertIn("aws_flow_log", results[0]["message"]["text"])

    def test_generate_sarif_with_drift_findings(self):
        drift = [
            {
                "resource_id": "s3-unencrypted-temp",
                "drift_type": "UNMANAGED_RESOURCE",
                "severity": "CRITICAL",
                "description": "S3 bucket created outside Terraform",
                "remediation": "Import into Terraform state",
            }
        ]
        sarif = generate_sarif(self.sample_results, framework="soc2", drift_findings=drift)
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        drift_result = next(r for r in run["results"] if r["ruleId"] == "DRIFT-UNMANAGED_RESOURCE")
        self.assertEqual(drift_result["level"], "error")
        self.assertIn("s3-unencrypted-temp", drift_result["message"]["text"])

    def test_save_sarif_file(self):
        sarif_data = generate_sarif(self.sample_results, framework="hipaa")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "subfolder" / "hipaa_compliance.sarif"
            saved_path = save_sarif(sarif_data, out_file)
            self.assertTrue(saved_path.exists())
            with open(saved_path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
