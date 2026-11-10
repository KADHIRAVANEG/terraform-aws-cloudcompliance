import unittest
from unittest.mock import patch, MagicMock

from cloudcompliance.notifications import (
    get_webhooks,
    send_slack,
    send_teams,
    send_discord,
    send_generic_webhook,
    dispatch_alert,
    notify_compliance_score,
    notify_drift,
)


class TestNotifications(unittest.TestCase):
    @patch.dict("os.environ", {
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/test",
        "TEAMS_WEBHOOK_URL": "https://company.webhook.office.com/webhookb2/test",
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test",
        "GENERIC_WEBHOOK_URL": "https://events.pagerduty.com/v2/enqueue",
    })
    def test_get_webhooks(self):
        hooks = get_webhooks()
        self.assertEqual(hooks["slack"], "https://hooks.slack.com/services/test")
        self.assertEqual(hooks["teams"], "https://company.webhook.office.com/webhookb2/test")
        self.assertEqual(hooks["discord"], "https://discord.com/api/webhooks/test")
        self.assertEqual(hooks["generic"], "https://events.pagerduty.com/v2/enqueue")

    @patch("requests.post")
    def test_send_slack(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        with patch.dict("os.environ", {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/test"}):
            success = send_slack({"text": "Test Slack Alert"})
            self.assertTrue(success)
            mock_post.assert_called_once()

    @patch("requests.post")
    def test_send_teams(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        with patch.dict("os.environ", {"TEAMS_WEBHOOK_URL": "https://company.webhook.office.com/webhookb2/test"}):
            success = send_teams(
                title="SOC2 Audit Passed",
                text="All controls satisfied",
                fields=[{"title": "Score", "value": "100%"}]
            )
            self.assertTrue(success)
            self.assertEqual(mock_post.call_args[1]["json"]["@type"], "MessageCard")

    @patch("requests.post")
    def test_send_discord(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_post.return_value = mock_resp

        with patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test"}):
            success = send_discord(
                title="Drift Detected",
                description="Unmanaged S3 bucket found",
                fields=[{"title": "Severity", "value": "HIGH"}]
            )
            self.assertTrue(success)
            self.assertEqual(mock_post.call_args[1]["json"]["username"], "CloudCompliance Bot")

    @patch("requests.post")
    def test_send_generic_webhook(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_post.return_value = mock_resp

        with patch.dict("os.environ", {"GENERIC_WEBHOOK_URL": "https://events.pagerduty.com/v2/enqueue"}):
            success = send_generic_webhook(
                event_type="Compliance Regression",
                data={"framework": "soc2", "score": 45},
                severity="CRITICAL"
            )
            self.assertTrue(success)
            payload = mock_post.call_args[1]["json"]
            self.assertEqual(payload["event_type"], "Compliance Regression")
            self.assertEqual(payload["severity"], "CRITICAL")

    @patch("requests.post")
    def test_dispatch_alert_multichannel(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        with patch.dict("os.environ", {
            "SLACK_WEBHOOK_URL": "https://slack.test",
            "TEAMS_WEBHOOK_URL": "https://teams.test",
            "DISCORD_WEBHOOK_URL": "https://discord.test",
            "GENERIC_WEBHOOK_URL": "https://generic.test",
        }):
            dispatch_alert(
                title="Multi-channel Test",
                summary="Broadcasting to all endpoints",
            )
            self.assertEqual(mock_post.call_count, 4)

    @patch("cloudcompliance.notifications.dispatch_alert")
    def test_notify_compliance_score(self, mock_dispatch):
        notify_compliance_score(score=92, passing=11, total=12, resources=46, framework="soc2")
        mock_dispatch.assert_called_once()
        call_kwargs = mock_dispatch.call_args[1]
        self.assertIn("SOC2 Compliance Report", call_kwargs["title"])
        self.assertEqual(call_kwargs["severity"], "INFO")


if __name__ == "__main__":
    unittest.main()
