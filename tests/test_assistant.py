import os
import unittest
from unittest.mock import MagicMock, patch

from cloudcompliance.assistant import (
    detect_provider,
    generate_offline_guidance,
    call_openai,
    call_anthropic,
    call_ollama,
    call_nvidia,
    ask,
)


class TestAssistant(unittest.TestCase):
    def test_detect_provider_explicit(self):
        p, m = detect_provider("openai", "gpt-4o")
        self.assertEqual(p, "openai")
        self.assertEqual(m, "gpt-4o")

        p, m = detect_provider("anthropic", "claude-3-opus")
        self.assertEqual(p, "anthropic")
        self.assertEqual(m, "claude-3-opus")

        p, m = detect_provider("ollama", "mistral")
        self.assertEqual(p, "ollama")
        self.assertEqual(m, "mistral")

        p, m = detect_provider("offline")
        self.assertEqual(p, "offline")

    def test_detect_provider_from_env(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-mock-key"}, clear=True):
            p, m = detect_provider()
            self.assertEqual(p, "openai")

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-mock"}, clear=True):
            p, m = detect_provider()
            self.assertEqual(p, "anthropic")

        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:11434"}, clear=True):
            p, m = detect_provider()
            self.assertEqual(p, "ollama")

        with patch.dict(os.environ, {}, clear=True):
            p, m = detect_provider()
            self.assertEqual(p, "offline")

    def test_generate_offline_guidance(self):
        context = {
            "compliance_report": {
                "compliance_score": 100,
                "controls": {"CC6.1": {"status": "PASS"}, "CC6.2": {"status": "PASS"}}
            },
            "resource_count": 42
        }
        res_audit = generate_offline_guidance("Are we ready for an audit?", context)
        self.assertIn("100% Compliance Score", res_audit)
        self.assertIn("CC6.1", res_audit)

        res_drift = generate_offline_guidance("How do I fix drift?", context)
        self.assertIn("cloudcompliance remediate", res_drift)

    @patch("requests.post")
    def test_call_openai(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OpenAI says compliant."}}]
        }
        mock_post.return_value = mock_resp

        ans = call_openai("system prompt", "user question", "gpt-4o", "sk-test")
        self.assertEqual(ans, "OpenAI says compliant.")

    @patch("requests.post")
    def test_call_anthropic(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [{"text": "Claude says SOC2 passing."}]
        }
        mock_post.return_value = mock_resp

        ans = call_anthropic("system prompt", "user question", "claude-3-5-sonnet", "sk-ant")
        self.assertEqual(ans, "Claude says SOC2 passing.")

    @patch("requests.post")
    def test_call_ollama(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "message": {"content": "Ollama local response."}
        }
        mock_post.return_value = mock_resp

        ans = call_ollama("system prompt", "user question", "llama3.2")
        self.assertEqual(ans, "Ollama local response.")

    def test_ask_offline_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            ans = ask("What is our posture?", provider="offline")
            self.assertIn("SOC2", ans)


if __name__ == "__main__":
    unittest.main()
