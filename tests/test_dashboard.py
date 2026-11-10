import unittest
from unittest.mock import MagicMock, patch
from starlette.testclient import TestClient

from cloudcompliance.dashboard import app


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_status_endpoint(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("compliance", data)
        self.assertIn("drift", data)
        self.assertIn("history", data)

    def test_framework_switch_endpoint(self):
        response = self.client.get("/api/framework/hipaa")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("framework"), "hipaa")

    def test_download_bundle_endpoint(self):
        response = self.client.get("/api/download/bundle")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/zip", response.headers.get("content-type", ""))
        self.assertGreater(len(response.content), 100)

    @patch("cloudcompliance.drift.detector.DriftDetector.run")
    def test_drift_action_endpoint(self, mock_run):
        mock_run.return_value = 0
        response = self.client.post("/api/actions/drift")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("drift_count", data)


if __name__ == "__main__":
    unittest.main()
