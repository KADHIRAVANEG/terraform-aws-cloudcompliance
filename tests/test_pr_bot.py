import unittest
from unittest.mock import patch, MagicMock

from cloudcompliance.pr_bot import generate_pr_comment, post_github_pr_comment


class TestPRBot(unittest.TestCase):
    def setUp(self):
        self.mock_current_results = {
            "CC6.1": {"title": "Network Isolation", "status": "PASS", "matched": ["aws_vpc"], "missing": []},
            "CC6.2": {"title": "Auth Controls", "status": "PASS", "matched": ["aws_iam_role"], "missing": []},
        }
        self.mock_resources = [{"type": "aws_vpc", "name": "vpc1"}, {"type": "aws_iam_role", "name": "r1"}]

    def test_generate_pr_comment_passing(self):
        comment, compliant = generate_pr_comment(
            current_results=self.mock_current_results,
            current_score=100,
            current_resources=self.mock_resources,
            min_score=80,
        )
        self.assertTrue(compliant)
        self.assertIn("PR PASSED", comment)
        self.assertIn("100%", comment)
        self.assertIn("Network Isolation", comment)

    def test_generate_pr_comment_blocked_below_threshold(self):
        comment, compliant = generate_pr_comment(
            current_results=self.mock_current_results,
            current_score=50,
            current_resources=self.mock_resources,
            min_score=80,
        )
        self.assertFalse(compliant)
        self.assertIn("PR BLOCKED", comment)

    def test_generate_pr_comment_regression(self):
        comment, compliant = generate_pr_comment(
            current_results=self.mock_current_results,
            current_score=85,
            current_resources=self.mock_resources,
            base_score=100,
            min_score=80,
            fail_on_regression=True,
        )
        self.assertFalse(compliant)
        self.assertIn("COMPLIANCE REGRESSION DETECTED", comment)

    @patch("requests.post")
    def test_post_github_pr_comment(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        success = post_github_pr_comment(
            comment_body="test comment",
            token="ghp_fake123",
            repo="owner/repo",
            pr_number=42,
        )
        self.assertTrue(success)
        mock_post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
