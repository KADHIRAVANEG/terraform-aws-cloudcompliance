import json
import os
import unittest
from unittest.mock import patch, MagicMock

from fastapi import HTTPException

from cloudcompliance.dashboard import (
    dashboard,
    download_audit_bundle,
    get_framework_report,
    get_status,
    trigger_drift_scan,
    sanitize_framework,
    get_allowed_origins,
    verify_token,
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

    def test_path_traversal_framework_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            sanitize_framework("../../etc/passwd")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Invalid framework", ctx.exception.detail)

    def test_valid_frameworks_pass_sanitization(self):
        self.assertEqual(sanitize_framework("soc2"), "soc2")
        self.assertEqual(sanitize_framework("HIPAA"), "hipaa")
        self.assertEqual(sanitize_framework("pcidss"), "pcidss")

    def test_allowed_origins_default_and_custom(self):
        defaults = get_allowed_origins()
        self.assertIn("http://localhost:8080", defaults)
        self.assertIn("http://127.0.0.1:8080", defaults)

        with patch.dict(os.environ, {"DASHBOARD_CORS_ORIGINS": "https://sec.internal,https://audit.corp"}):
            custom = get_allowed_origins()
            self.assertEqual(custom, ["https://sec.internal", "https://audit.corp"])

    def test_token_auth_enforcement(self):
        with patch.dict(os.environ, {"CLOUDCOMPLIANCE_API_KEY": "supersecret123"}):
            # Unauthenticated request should raise 401
            mock_unauth_req = MagicMock()
            mock_unauth_req.headers = {}
            mock_unauth_req.query_params = {}
            with self.assertRaises(HTTPException) as ctx:
                verify_token(mock_unauth_req)
            self.assertEqual(ctx.exception.status_code, 401)

            # Bearer token authenticated request should succeed
            mock_bearer_req = MagicMock()
            mock_bearer_req.headers = {"Authorization": "Bearer supersecret123"}
            mock_bearer_req.query_params = {}
            self.assertTrue(verify_token(mock_bearer_req))

            # X-API-Key authenticated request should succeed
            mock_apikey_req = MagicMock()
            mock_apikey_req.headers = {"X-API-Key": "supersecret123"}
            mock_apikey_req.query_params = {}
            self.assertTrue(verify_token(mock_apikey_req))

            # Query param token authenticated request should succeed
            mock_query_req = MagicMock()
            mock_query_req.headers = {}
            mock_query_req.query_params = {"token": "supersecret123"}
            self.assertTrue(verify_token(mock_query_req))


if __name__ == "__main__":
    unittest.main()
