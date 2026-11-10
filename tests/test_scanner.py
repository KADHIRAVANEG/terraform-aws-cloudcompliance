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

    @patch("boto3.Session")
    def test_scanner_multi_region(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]
        }
        mock_client.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-multi"}]}
        mock_client.describe_subnets.return_value = {"Subnets": []}
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_client.describe_flow_logs.return_value = {"FlowLogs": []}

        # Test explicit regions
        scanner = LiveAWSScanner(regions=["us-east-1", "eu-west-1"])
        self.assertEqual(scanner.get_target_regions(), ["us-east-1", "eu-west-1"])

        # Test all_regions flag
        scanner_all = LiveAWSScanner(all_regions=True)
        regions = scanner_all.get_target_regions()
        self.assertEqual(regions, ["us-east-1", "eu-west-1"])

        scanner.scan_vpc()
        # Scan ran across 2 regions -> 2 VPC resources added
        vpc_resources = [r for r in scanner.discovered_resources if r["type"] == "aws_vpc"]
        self.assertEqual(len(vpc_resources), 2)
        regions_found = {r["region"] for r in vpc_resources}
        self.assertEqual(regions_found, {"us-east-1", "eu-west-1"})


if __name__ == "__main__":
    unittest.main()
