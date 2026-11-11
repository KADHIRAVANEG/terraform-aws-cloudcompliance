import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cloudcompliance.remediation import RemediationEngine, LOW_RISK, HIGH_RISK, CRITICAL


class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.comp_dir = Path(self.temp_dir.name) / "compliance"
        self.comp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_classify_risk(self):
        engine = RemediationEngine(compliance_dir=self.comp_dir)
        self.assertEqual(engine.classify_risk({"severity": "MEDIUM"}), LOW_RISK)
        self.assertEqual(engine.classify_risk({"severity": "HIGH"}), HIGH_RISK)
        self.assertEqual(engine.classify_risk({"severity": "CRITICAL"}), CRITICAL)
        self.assertEqual(engine.classify_risk({}), LOW_RISK)

    def test_remediate_unmanaged_bucket_dry_run(self):
        engine = RemediationEngine(dry_run=True, compliance_dir=self.comp_dir)
        finding = {
            "resource_id": "test-bucket-orphan",
            "severity": "MEDIUM",
            "drift_type": "UNMANAGED",
            "description": "Bucket not in tfstate"
        }
        with patch.object(engine, "_client") as mock_client:
            engine.remediate_unmanaged_bucket(finding)
            mock_client.assert_not_called()
        self.assertEqual(len(engine.actions_taken), 0)

    @patch("cloudcompliance.remediation.RemediationEngine.open_github_pr")
    def test_remediate_unmanaged_bucket_live(self, mock_open_pr):
        engine = RemediationEngine(dry_run=False, compliance_dir=self.comp_dir)
        mock_s3 = MagicMock()
        finding = {
            "resource_id": "orphan-bucket",
            "severity": "MEDIUM",
            "drift_type": "UNMANAGED",
        }
        with patch.object(engine, "_client", return_value=mock_s3):
            engine.remediate_unmanaged_bucket(finding)
            mock_s3.put_bucket_tagging.assert_called_once()
            call_kwargs = mock_s3.put_bucket_tagging.call_args[1]
            self.assertEqual(call_kwargs["Bucket"], "orphan-bucket")
            tags = {t["Key"]: t["Value"] for t in call_kwargs["Tagging"]["TagSet"]}
            self.assertEqual(tags["ManagedBy"], "CloudCompliance")
            self.assertEqual(tags["Status"], "PendingTerraformImport")
            mock_open_pr.assert_called_once()

    def test_open_github_pr_without_token(self):
        engine = RemediationEngine(compliance_dir=self.comp_dir)
        engine.github_token = None
        finding = {"resource_id": "res-1", "severity": "HIGH", "description": "High risk change"}
        engine.open_github_pr(finding)
        self.assertEqual(len(engine.prs_opened), 0)

    @patch("requests.post")
    @patch("requests.put")
    @patch("requests.get")
    def test_open_github_pr_success(self, mock_get, mock_put, mock_post):
        engine = RemediationEngine(compliance_dir=self.comp_dir)
        engine.github_token = "ghp_mock_token"

        # Mock GET repo
        mock_repo_resp = MagicMock()
        mock_repo_resp.json.return_value = {"default_branch": "main"}
        mock_repo_resp.status_code = 200

        # Mock GET ref sha
        mock_ref_resp = MagicMock()
        mock_ref_resp.json.return_value = {"object": {"sha": "abc123sha"}}
        mock_ref_resp.status_code = 200

        mock_get.side_effect = [mock_repo_resp, mock_ref_resp]

        # Mock POST create branch
        mock_branch_resp = MagicMock()
        mock_branch_resp.status_code = 201

        # Mock POST create PR
        mock_pr_resp = MagicMock()
        mock_pr_resp.status_code = 201
        mock_pr_resp.json.return_value = {"html_url": "https://github.com/owner/repo/pull/101"}

        mock_post.side_effect = [mock_branch_resp, mock_pr_resp]

        # Mock PUT commit file
        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 201
        mock_put.return_value = mock_put_resp

        finding = {
            "resource_id": "test-sec-group",
            "severity": "HIGH",
            "description": "Ingress rule 0.0.0.0/0 detected",
            "remediation": "Restrict security group ingress."
        }

        with patch("cloudcompliance.notifications.notify_remediation"):
            engine.open_github_pr(finding)

        self.assertEqual(len(engine.prs_opened), 1)
        self.assertEqual(engine.prs_opened[0]["pr_url"], "https://github.com/owner/repo/pull/101")

    def test_run_empty_drift(self):
        engine = RemediationEngine(compliance_dir=self.comp_dir)
        report_file = self.comp_dir / "drift_report.json"
        with open(report_file, "w") as f:
            json.dump({"drift_count": 0, "findings": []}, f)

        engine.run()
        self.assertEqual(len(engine.actions_taken), 0)
        self.assertEqual(len(engine.prs_opened), 0)


if __name__ == "__main__":
    unittest.main()
