import unittest
from unittest.mock import patch
import sys

from cloudcompliance.cli import main


class TestCLI(unittest.TestCase):
    @patch("cloudcompliance.cli.load_tfstate")
    @patch("cloudcompliance.cli.print_report")
    def test_cli_report_default(self, mock_print_report, mock_load_tfstate):
        mock_load_tfstate.return_value = {"resources": []}
        test_args = ["cloudcompliance", "report", "--framework", "soc2", "--pdf"]
        with patch.object(sys, "argv", test_args):
            main()
            self.assertTrue(mock_print_report.called)
            # Verify pdf=True passed
            _, kwargs = mock_print_report.call_args
            self.assertTrue(kwargs.get("pdf"))

    @patch("cloudcompliance.history.show_history")
    def test_cli_history(self, mock_show_history):
        test_args = ["cloudcompliance", "history", "--limit", "5"]
        with patch.object(sys, "argv", test_args):
            main()
            mock_show_history.assert_called_once_with(limit=5)

    @patch("cloudcompliance.scanner.LiveAWSScanner.evaluate")
    def test_cli_scan(self, mock_evaluate):
        test_args = ["cloudcompliance", "scan", "--live", "--framework", "soc2"]
        with patch.object(sys, "argv", test_args):
            main()
            mock_evaluate.assert_called_once()

    @patch("cloudcompliance.pr_bot.run_pr_check")
    def test_cli_pr_check(self, mock_run_pr_check):
        mock_run_pr_check.return_value = 0
        test_args = ["cloudcompliance", "pr-check", "--min-score", "85"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)
            mock_run_pr_check.assert_called_once()


    @patch("cloudcompliance.cli.load_tfstate")
    @patch("cloudcompliance.cli.print_report")
    def test_cli_report_sarif(self, mock_print_report, mock_load_tfstate):
        mock_load_tfstate.return_value = {"resources": []}
        test_args = ["cloudcompliance", "report", "--sarif"]
        with patch.object(sys, "argv", test_args):
            main()
            self.assertTrue(mock_print_report.called)
            _, kwargs = mock_print_report.call_args
            self.assertTrue(kwargs.get("sarif"))

    @patch("cloudcompliance.wizard.run_wizard")
    def test_cli_init(self, mock_run_wizard):
        test_args = ["cloudcompliance", "init", "--provider", "aws", "--non-interactive"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)
            mock_run_wizard.assert_called_once()

    @patch("cloudcompliance.scanner.LiveAWSScanner.evaluate")
    def test_cli_scan_all_regions(self, mock_evaluate):
        test_args = ["cloudcompliance", "scan", "--all-regions", "--sarif"]
        with patch.object(sys, "argv", test_args):
            main()
            mock_evaluate.assert_called_once()
            _, kwargs = mock_evaluate.call_args
            self.assertTrue(kwargs.get("sarif"))


if __name__ == "__main__":
    unittest.main()
