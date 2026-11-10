#!/usr/bin/env python3
"""
CloudCompliance — Live Agentless Cloud Security Posture Management (CSPM) Scanner
Queries AWS APIs directly via boto3 to evaluate SOC2/HIPAA/PCI-DSS compliance
without requiring terraform.tfstate.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import boto3
from rich.console import Console

from cloudcompliance.report import (
    evaluate_controls,
    get_default_compliance_dir,
    load_controls,
    print_report,
)

console = Console()


class LiveAWSScanner:
    """Agentless CSPM Scanner inspecting live AWS environment."""

    def __init__(self, endpoint_url: Optional[str] = None, region: Optional[str] = None):
        self.endpoint_url = endpoint_url or os.getenv("AWS_ENDPOINT_URL") or os.getenv("LOCALSTACK_ENDPOINT")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1"))

        session_kwargs = {"region_name": self.region}
        is_local = self.endpoint_url and (
            "localhost" in self.endpoint_url
            or "127.0.0.1" in self.endpoint_url
            or "localstack" in self.endpoint_url
        )
        if is_local and not os.getenv("AWS_ACCESS_KEY_ID"):
            session_kwargs["aws_access_key_id"] = "test"
            session_kwargs["aws_secret_access_key"] = "test"

        self.session = boto3.Session(**session_kwargs)
        self.discovered_resources: List[Dict[str, Any]] = []

    def _client(self, service: str):
        kwargs = {}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return self.session.client(service, **kwargs)

    def _add_resource(self, res_type: str, name: str, attributes: Optional[Dict[str, Any]] = None, tags: Optional[Dict[str, str]] = None):
        self.discovered_resources.append({
            "type": res_type,
            "name": name,
            "module": "live_aws",
            "attributes": attributes or {},
            "tags": tags or {},
            "live": True,
        })

    def scan_s3(self):
        """Discover S3 buckets, encryption, public access block, versioning, policies."""
        console.print("[dim]  Scanning S3 storage & access boundaries...[/dim]")
        s3 = self._client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            console.print(f"[yellow]  Warning scanning S3: {e}[/yellow]")
            return

        for b in buckets:
            bname = b.get("Name")
            self._add_resource("aws_s3_bucket", bname)

            # Check encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=bname)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    self._add_resource("aws_s3_bucket_server_side_encryption_configuration", f"{bname}_encryption")
            except Exception:
                pass

            # Check public access block
            try:
                pab = s3.get_public_access_block(Bucket=bname)
                conf = pab.get("PublicAccessBlockConfiguration", {})
                if any(conf.values()):
                    self._add_resource("aws_s3_bucket_public_access_block", f"{bname}_pab")
            except Exception:
                pass

            # Check versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=bname)
                if ver.get("Status") == "Enabled":
                    self._add_resource("aws_s3_bucket_versioning", f"{bname}_versioning")
            except Exception:
                pass

            # Check bucket policy
            try:
                pol = s3.get_bucket_policy(Bucket=bname)
                if pol.get("Policy"):
                    self._add_resource("aws_s3_bucket_policy", f"{bname}_policy")
            except Exception:
                pass

    def scan_iam(self):
        """Discover IAM password policy, roles, and policies."""
        console.print("[dim]  Scanning IAM identity & access governance...[/dim]")
        iam = self._client("iam")

        # Account password policy
        try:
            pw_pol = iam.get_account_password_policy().get("PasswordPolicy", {})
            if pw_pol:
                self._add_resource("aws_iam_account_password_policy", "account_password_policy", pw_pol)
        except Exception:
            pass

        # Roles & role policies
        try:
            roles = iam.list_roles().get("Roles", [])
            for r in roles:
                rname = r.get("RoleName")
                self._add_resource("aws_iam_role", rname)
                try:
                    pols = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
                    for p in pols:
                        self._add_resource("aws_iam_role_policy", f"{rname}_{p}")
                    attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                    for a in attached:
                        self._add_resource("aws_iam_role_policy_attachment", f"{rname}_{a.get('PolicyName')}")
                except Exception:
                    pass
        except Exception as e:
            console.print(f"[yellow]  Warning scanning IAM roles: {e}[/yellow]")

        # Customer managed policies
        try:
            pols = iam.list_policies(Scope="Local").get("Policies", [])
            for p in pols:
                self._add_resource("aws_iam_policy", p.get("PolicyName"))
        except Exception:
            pass

    def scan_kms(self):
        """Discover customer managed KMS keys and aliases."""
        console.print("[dim]  Scanning KMS cryptographic key management...[/dim]")
        kms = self._client("kms")
        try:
            keys = kms.list_keys().get("Keys", [])
            for k in keys:
                kid = k.get("KeyId")
                self._add_resource("aws_kms_key", kid)
        except Exception as e:
            console.print(f"[yellow]  Warning scanning KMS keys: {e}[/yellow]")

        try:
            aliases = kms.list_aliases().get("Aliases", [])
            for a in aliases:
                aname = a.get("AliasName")
                if not aname.startswith("alias/aws/"):
                    self._add_resource("aws_kms_alias", aname)
        except Exception:
            pass

    def scan_vpc(self):
        """Discover VPCs, subnets, security groups, and flow logs."""
        console.print("[dim]  Scanning VPC network isolation & boundary controls...[/dim]")
        ec2 = self._client("ec2")

        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for v in vpcs:
                self._add_resource("aws_vpc", v.get("VpcId"))
        except Exception as e:
            console.print(f"[yellow]  Warning scanning VPCs: {e}[/yellow]")

        try:
            subnets = ec2.describe_subnets().get("Subnets", [])
            for s in subnets:
                self._add_resource("aws_subnet", s.get("SubnetId"))
        except Exception:
            pass

        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                if sg.get("GroupName") == "default":
                    self._add_resource("aws_default_security_group", sg.get("GroupId"))
                else:
                    self._add_resource("aws_security_group", sg.get("GroupId"))
        except Exception:
            pass

        try:
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            for fl in flow_logs:
                self._add_resource("aws_flow_log", fl.get("FlowLogId"))
        except Exception:
            pass

    def scan_cloudwatch_and_trails(self):
        """Discover CloudTrail audit trails and CloudWatch log groups/alarms."""
        console.print("[dim]  Scanning CloudTrail & CloudWatch audit pipelines...[/dim]")
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                self._add_resource("aws_cloudtrail", t.get("Name"))
        except Exception:
            pass

        try:
            logs = self._client("logs")
            groups = logs.describe_log_groups().get("logGroups", [])
            for lg in groups:
                self._add_resource("aws_cloudwatch_log_group", lg.get("logGroupName"))

            filters = logs.describe_metric_filters().get("metricFilters", [])
            for mf in filters:
                self._add_resource("aws_cloudwatch_log_metric_filter", mf.get("filterName"))
        except Exception:
            pass

        try:
            cw = self._client("cloudwatch")
            alarms = cw.describe_alarms().get("MetricAlarms", [])
            for al in alarms:
                self._add_resource("aws_cloudwatch_metric_alarm", al.get("AlarmName"))
        except Exception:
            pass

    def scan_config_and_sns(self):
        """Discover AWS Config recorders and SNS notification topics."""
        console.print("[dim]  Scanning AWS Config continuous governance & alerting...[/dim]")
        try:
            cfg = self._client("config")
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            for r in recorders:
                self._add_resource("aws_config_configuration_recorder", r.get("name"))

            statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            for s in statuses:
                if s.get("recording"):
                    self._add_resource("aws_config_configuration_recorder_status", s.get("name"))

            channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
            for d in channels:
                self._add_resource("aws_config_delivery_channel", d.get("name"))

            rules = cfg.describe_config_rules().get("ConfigRules", [])
            for rule in rules:
                self._add_resource("aws_config_config_rule", rule.get("ConfigRuleName"))
        except Exception:
            pass

        try:
            sns = self._client("sns")
            topics = sns.list_topics().get("Topics", [])
            for t in topics:
                self._add_resource("aws_sns_topic", t.get("TopicArn", "").split(":")[-1])
        except Exception:
            pass

    def run_scan(self) -> List[Dict[str, Any]]:
        """Run full agentless inventory scan of the target AWS account."""
        self.discovered_resources = []
        self.scan_s3()
        self.scan_iam()
        self.scan_kms()
        self.scan_vpc()
        self.scan_cloudwatch_and_trails()
        self.scan_config_and_sns()
        return self.discovered_resources

    def evaluate(
        self,
        framework: str = "soc2",
        output_dir: Optional[Path] = None,
        pdf: bool = False,
    ) -> Dict[str, Any]:
        """Perform agentless scan and evaluate controls against framework."""
        console.print(f"\n[bold cyan]CloudCompliance — Starting Agentless Live AWS Audit[/bold cyan]")
        console.print(f"[dim]Region: {self.region} | Endpoint: {self.endpoint_url or 'Default AWS'}[/dim]\n")

        resources = self.run_scan()
        console.print(f"\n[green]Discovered {len(resources)} active cloud resources via AWS APIs[/green]")

        controls = load_controls(framework)
        results = evaluate_controls(resources, controls, provider="aws")

        out_dir = Path(output_dir) if output_dir else get_default_compliance_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        print_report(
            results,
            resources,
            output_path=out_dir / f"live_aws_{framework}_report.json",
            framework=framework,
            output_dir=out_dir,
            pdf=pdf,
        )
        return results
