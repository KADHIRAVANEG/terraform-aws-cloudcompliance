import unittest
from unittest.mock import MagicMock, patch

from cloudcompliance.scanner import LiveAWSScanner


class TestLiveAWSScanner(unittest.TestCase):
    @patch("boto3.Session")
    def test_scanner_s3(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "prod-data-bucket"}]}
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        }
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
        }
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_s3.get_bucket_policy.return_value = {"Policy": '{"Statement":[]}'}

        scanner = LiveAWSScanner()
        scanner.scan_s3()

        res_types = [r["type"] for r in scanner.discovered_resources]
        self.assertIn("aws_s3_bucket", res_types)
        self.assertIn("aws_s3_bucket_server_side_encryption_configuration", res_types)
        self.assertIn("aws_s3_bucket_public_access_block", res_types)
        self.assertIn("aws_s3_bucket_versioning", res_types)
        self.assertIn("aws_s3_bucket_policy", res_types)

    @patch("boto3.Session")
    def test_scanner_vpc_and_kms(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-12345"}]}
        mock_client.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-12345"}]}
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-123", "GroupName": "default"}]
        }
        mock_client.describe_flow_logs.return_value = {"FlowLogs": [{"FlowLogId": "fl-123"}]}

        mock_client.list_keys.return_value = {"Keys": [{"KeyId": "key-123"}]}
        mock_client.list_aliases.return_value = {"Aliases": [{"AliasName": "alias/custom-key"}]}

        scanner = LiveAWSScanner()
        scanner.scan_vpc()
        scanner.scan_kms()

        res_types = [r["type"] for r in scanner.discovered_resources]
        self.assertIn("aws_vpc", res_types)
        self.assertIn("aws_subnet", res_types)
        self.assertIn("aws_default_security_group", res_types)
        self.assertIn("aws_flow_log", res_types)
        self.assertIn("aws_kms_key", res_types)
        self.assertIn("aws_kms_alias", res_types)


if __name__ == "__main__":
    unittest.main()
