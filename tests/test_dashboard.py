import json
import unittest
from unittest.mock import patch

from cloudcompliance.dashboard import (
    dashboard,
    download_audit_bundle,
    get_framework_report,
    get_status,
    trigger_drift_scan,
)


class TestDashboard(unittest.TestCase):
    def test_status_endpoint(self):
        response = get_status()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.body.decode("utf-8"))
        self.assertIn("compliance", data)
        self.assertIn("drift", data)
        self.assertIn("history", data)

    def test_framework_switch_endpoint(self):
        response = get_framework_report("hipaa")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.body.decode("utf-8"))
        self.assertEqual(data.get("framework"), "hipaa")

    def test_download_bundle_endpoint(self):
        response = download_audit_bundle()
        self.assertEqual(response.status_code, 200)
        headers = dict(response.headers)
        self.assertIn("application/zip", headers.get("content-type", ""))
        self.assertGreater(len(response.body), 100)

    @patch("cloudcompliance.drift.detector.DriftDetector.run")
    def test_drift_action_endpoint(self, mock_run):
        mock_run.return_value = 0
        response = trigger_drift_scan()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.body.decode("utf-8"))
        self.assertIn("drift_count", data)

    def test_dashboard_html(self):
        response = dashboard()
        self.assertEqual(response.status_code, 200)
        self.assertIn("CloudCompliance", response.body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
