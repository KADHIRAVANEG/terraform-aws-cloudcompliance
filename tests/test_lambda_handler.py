import json
import os
import unittest
from unittest.mock import MagicMock, patch

from cloudcompliance.lambda_handler import handler


class TestLambdaHandler(unittest.TestCase):
    def test_missing_tfstate_url_returns_500(self):
        with patch.dict(os.environ, {}, clear=True):
            resp = handler({}, None)
            self.assertEqual(resp["statusCode"], 500)
            self.assertIn("TFSTATE_URL not configured", resp["body"])

    @patch("cloudcompliance.lambda_handler.DriftDetector")
    def test_compliant_no_drift(self, mock_detector_cls):
        mock_instance = MagicMock()
        mock_instance.run.return_value = 0
        mock_detector_cls.return_value = mock_instance

        with patch.dict(os.environ, {"TFSTATE_URL": "s3://test-bucket/terraform.tfstate"}):
            resp = handler({"detail": {"eventName": "CreateBucket"}}, None)
            self.assertEqual(resp["statusCode"], 200)
            body = json.loads(resp["body"])
            self.assertEqual(body["status"], "COMPLIANT")
            self.assertEqual(body["drift_count"], 0)

    @patch("cloudcompliance.lambda_handler.DriftDetector")
    def test_drift_detected_without_auto_remediation(self, mock_detector_cls):
        mock_instance = MagicMock()
        mock_instance.run.return_value = 2
        mock_instance.drift_findings = [
            {"resource_id": "unmanaged-bucket", "severity": "MEDIUM"}
        ]
        mock_detector_cls.return_value = mock_instance

        with patch.dict(os.environ, {"TFSTATE_URL": "s3://test-bucket/terraform.tfstate", "AUTO_REMEDIATE": "false"}):
            resp = handler({"detail": {"eventName": "CreateBucket"}}, None)
            self.assertEqual(resp["statusCode"], 200)
            body = json.loads(resp["body"])
            self.assertEqual(body["status"], "DRIFT_DETECTED")
            self.assertEqual(body["drift_count"], 2)
            self.assertEqual(len(body["findings"]), 1)

    @patch("cloudcompliance.remediation.RemediationEngine")
    @patch("cloudcompliance.lambda_handler.DriftDetector")
    def test_drift_detected_with_auto_remediation(self, mock_detector_cls, mock_engine_cls):
        mock_detector = MagicMock()
        mock_detector.run.return_value = 1
        mock_detector.drift_findings = [{"resource_id": "b1", "severity": "LOW"}]
        mock_detector_cls.return_value = mock_detector

        mock_engine = MagicMock()
        mock_engine_cls.return_value = mock_engine

        with patch.dict(os.environ, {"TFSTATE_URL": "s3://test-bucket/terraform.tfstate", "AUTO_REMEDIATE": "true"}):
            resp = handler({}, None)
            self.assertEqual(resp["statusCode"], 200)
            mock_engine.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
