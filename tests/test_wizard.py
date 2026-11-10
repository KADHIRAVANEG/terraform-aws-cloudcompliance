import tempfile
import unittest
from pathlib import Path

from cloudcompliance.wizard import run_wizard


class TestWizard(unittest.TestCase):
    def test_run_wizard_non_interactive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir)
            created = run_wizard(
                provider="aws",
                framework="soc2",
                env="staging",
                project_name="fintech-api",
                region="eu-west-1",
                output_dir=out_path,
                non_interactive=True,
            )

            self.assertIn("main.tf", created)
            self.assertIn("variables.tf", created)
            self.assertIn("terraform.tfvars", created)
            self.assertIn(".env.example", created)

            # Validate main.tf content
            main_tf = created["main.tf"].read_text()
            self.assertIn("aws_kms_key", main_tf)
            self.assertIn("aws_s3_bucket", main_tf)
            self.assertIn("aws_cloudtrail", main_tf)
            self.assertIn("aws_vpc", main_tf)
            self.assertIn("aws_flow_log", main_tf)

            # Validate variables.tf and tfvars
            tfvars = created["terraform.tfvars"].read_text()
            self.assertIn('aws_region               = "eu-west-1"', tfvars)
            self.assertIn('environment              = "staging"', tfvars)
            self.assertIn('project_name             = "fintech-api"', tfvars)

            # Validate .env.example
            env_file = created[".env.example"].read_text()
            self.assertIn("AWS_DEFAULT_REGION=eu-west-1", env_file)
            self.assertIn("TEAMS_WEBHOOK_URL=", env_file)
            self.assertIn("DISCORD_WEBHOOK_URL=", env_file)


if __name__ == "__main__":
    unittest.main()
