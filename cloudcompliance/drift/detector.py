#!/usr/bin/env python3
"""
CloudCompliance — Drift Detector
Compares live AWS resource state against terraform.tfstate
Alerts when infrastructure changes outside of Terraform
"""

import json
import boto3
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class DriftDetector:
    def __init__(self, tfstate_path: str, endpoint_url: str = None):
        self.tfstate_path = Path(tfstate_path)
        self.endpoint_url = endpoint_url
        self.session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name="us-east-1"
        )
        self.drift_findings = []

    def _client(self, service: str):
        kwargs = {"region_name": "us-east-1"}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return self.session.client(
            service,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            **kwargs
        )

    def load_tfstate(self) -> dict:
        if not self.tfstate_path.exists():
            console.print(f"[red]Error: tfstate not found at {self.tfstate_path}[/red]")
            sys.exit(1)
        with open(self.tfstate_path) as f:
            return json.load(f)

    def extract_tfstate_resources(self, tfstate: dict) -> dict:
        resources = {}
        for resource in tfstate.get("resources", []):
            rtype = resource.get("type")
            rname = resource.get("name")
            instances = resource.get("instances", [])
            if instances:
                attrs = instances[0].get("attributes", {})
                key = f"{rtype}.{rname}"
                resources[key] = attrs
        return resources

    def check_s3_buckets(self, tfstate_resources: dict):
        console.print("[dim]Checking S3 buckets...[/dim]")
        s3 = self._client("s3")

        tf_buckets = {
            attrs.get("bucket"): key
            for key, attrs in tfstate_resources.items()
            if key.startswith("aws_s3_bucket.")
            and attrs.get("bucket")
        }

        try:
            response = s3.list_buckets()
            live_buckets = {b["Name"] for b in response.get("Buckets", [])}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list S3 buckets: {e}[/yellow]")
            return

        # Check for deleted buckets
        for bucket_name, tf_key in tf_buckets.items():
            if bucket_name not in live_buckets:
                self.drift_findings.append({
                    "resource": tf_key,
                    "resource_id": bucket_name,
                    "drift_type": "DELETED",
                    "severity": "HIGH",
                    "description": f"S3 bucket '{bucket_name}' exists in Terraform state but not in AWS",
                    "remediation": f"Run 'terraform apply' to recreate or 'terraform state rm {tf_key}' to remove from state"
                })

        # Check for unmanaged buckets
        tf_bucket_names = set(tf_buckets.keys())
        for bucket_name in live_buckets:
            if bucket_name not in tf_bucket_names:
                self.drift_findings.append({
                    "resource": "aws_s3_bucket.unknown",
                    "resource_id": bucket_name,
                    "drift_type": "UNMANAGED",
                    "severity": "MEDIUM",
                    "description": f"S3 bucket '{bucket_name}' exists in AWS but not in Terraform state",
                    "remediation": f"Run 'terraform import aws_s3_bucket.{bucket_name} {bucket_name}' or delete if not needed"
                })

    def check_iam_roles(self, tfstate_resources: dict):
        console.print("[dim]Checking IAM roles...[/dim]")
        iam = self._client("iam")

        tf_roles = {
            attrs.get("name"): key
            for key, attrs in tfstate_resources.items()
            if key.startswith("aws_iam_role.")
            and attrs.get("name")
        }

        try:
            paginator = iam.get_paginator("list_roles")
            live_roles = set()
            for page in paginator.paginate():
                for role in page["Roles"]:
                    live_roles.add(role["RoleName"])
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list IAM roles: {e}[/yellow]")
            return

        for role_name, tf_key in tf_roles.items():
            if role_name not in live_roles:
                self.drift_findings.append({
                    "resource": tf_key,
                    "resource_id": role_name,
                    "drift_type": "DELETED",
                    "severity": "HIGH",
                    "description": f"IAM role '{role_name}' exists in Terraform state but not in AWS",
                    "remediation": f"Run 'terraform apply' to recreate the role"
                })

    def check_vpc(self, tfstate_resources: dict):
        console.print("[dim]Checking VPCs...[/dim]")
        ec2 = self._client("ec2")

        tf_vpcs = {
            attrs.get("id"): key
            for key, attrs in tfstate_resources.items()
            if key.startswith("aws_vpc.")
            and attrs.get("id")
        }

        try:
            response = ec2.describe_vpcs()
            live_vpcs = {v["VpcId"] for v in response.get("Vpcs", [])}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list VPCs: {e}[/yellow]")
            return

        for vpc_id, tf_key in tf_vpcs.items():
            if vpc_id not in live_vpcs:
                self.drift_findings.append({
                    "resource": tf_key,
                    "resource_id": vpc_id,
                    "drift_type": "DELETED",
                    "severity": "CRITICAL",
                    "description": f"VPC '{vpc_id}' exists in Terraform state but not in AWS — network isolation broken",
                    "remediation": "Run 'terraform apply' immediately to restore network isolation"
                })

    def check_kms_keys(self, tfstate_resources: dict):
        console.print("[dim]Checking KMS keys...[/dim]")
        kms = self._client("kms")

        tf_keys = {
            attrs.get("id"): key
            for key, attrs in tfstate_resources.items()
            if key.startswith("aws_kms_key.")
            and attrs.get("id")
        }

        try:
            paginator = kms.get_paginator("list_keys")
            live_keys = set()
            for page in paginator.paginate():
                for k in page["Keys"]:
                    live_keys.add(k["KeyId"])
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list KMS keys: {e}[/yellow]")
            return

        for key_id, tf_key in tf_keys.items():
            if key_id not in live_keys:
                self.drift_findings.append({
                    "resource": tf_key,
                    "resource_id": key_id,
                    "drift_type": "DELETED",
                    "severity": "CRITICAL",
                    "description": f"KMS key '{key_id}' deleted — encryption controls broken",
                    "remediation": "Run 'terraform apply' to restore encryption key"
                })




    def send_alert(self, drift_count: int):
        if drift_count == 0:
            from cloudcompliance.notifications import notify_no_drift
            notify_no_drift()
            return

        sns = self._client("sns")
        try:
            topics = sns.list_topics().get("Topics", [])
            alert_topic = next(
                (t["TopicArn"] for t in topics
                 if "root-account-alert" in t["TopicArn"]),
                None
            )
            if alert_topic:
                sns.publish(
                    TopicArn=alert_topic,
                    Subject=f"CloudCompliance: {drift_count} drift findings detected",
                    Message=json.dumps({
                        "alert_type": "DRIFT_DETECTED",
                        "drift_count": drift_count,
                        "timestamp": datetime.now().isoformat(),
                        "findings": self.drift_findings
                    }, indent=2)
                )
                console.print(f"[green]Alert sent to SNS topic[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not send SNS alert: {e}[/yellow]")

        from cloudcompliance.notifications import notify_drift
        notify_drift(self.drift_findings, drift_count)
        sns = self._client("sns")
        try:
            topics = sns.list_topics().get("Topics", [])
            alert_topic = next(
                (t["TopicArn"] for t in topics
                 if "root-account-alert" in t["TopicArn"]),
                None
            )
            if alert_topic:
                sns.publish(
                    TopicArn=alert_topic,
                    Subject=f"CloudCompliance: {drift_count} drift findings detected",
                    Message=json.dumps({
                        "alert_type": "DRIFT_DETECTED",
                        "drift_count": drift_count,
                        "timestamp": datetime.now().isoformat(),
                        "findings": self.drift_findings
                    }, indent=2)
                )
                console.print(f"[green]Alert sent to SNS topic[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not send SNS alert: {e}[/yellow]")

    def print_results(self):
        console.print()
        console.print(Panel.fit(
            "[bold cyan]CloudCompliance — Drift Detection Report[/bold cyan]\n"
            f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
            f"[dim]Comparing live AWS state against terraform.tfstate[/dim]",
            border_style="cyan"
        ))
        console.print()

        if not self.drift_findings:
            console.print(Panel.fit(
                "[bold green]✅ No drift detected — infrastructure matches Terraform state[/bold green]",
                border_style="green"
            ))
            return

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Severity", width=10)
        table.add_column("Resource", width=30)
        table.add_column("Drift Type", width=12)
        table.add_column("Description", width=45)

        for finding in self.drift_findings:
            severity = finding["severity"]
            if severity == "CRITICAL":
                sev_str = "[red]🔴 CRITICAL[/red]"
            elif severity == "HIGH":
                sev_str = "[yellow]🟡 HIGH[/yellow]"
            else:
                sev_str = "[blue]🔵 MEDIUM[/blue]"

            table.add_row(
                sev_str,
                finding["resource_id"],
                finding["drift_type"],
                finding["description"][:45]
            )

        console.print(table)
        console.print()

        console.print("[bold]Remediation steps:[/bold]")
        for i, finding in enumerate(self.drift_findings, 1):
            console.print(f"  [dim]{i}.[/dim] {finding['remediation']}")

        console.print()
        color = "red" if any(f["severity"] == "CRITICAL" for f in self.drift_findings) else "yellow"
        console.print(Panel.fit(
            f"[bold {color}]{len(self.drift_findings)} drift finding(s) detected — run 'terraform apply' to remediate[/bold {color}]",
            border_style=color
        ))

        output = {
            "generated_at": datetime.now().isoformat(),
            "drift_count": len(self.drift_findings),
            "findings": self.drift_findings
        }
        output_path = Path(__file__).parent.parent.parent / "compliance" / "drift_report.json"
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)
        console.print(f"\n[dim]Drift report saved → {output_path}[/dim]")

    def run(self):
        tfstate = self.load_tfstate()
        tfstate_resources = self.extract_tfstate_resources(tfstate)

        console.print(f"[dim]Loaded {len(tfstate_resources)} resources from Terraform state[/dim]")
        console.print()

        self.check_s3_buckets(tfstate_resources)
        self.check_iam_roles(tfstate_resources)
        self.check_vpc(tfstate_resources)
        self.check_kms_keys(tfstate_resources)

        self.send_alert(len(self.drift_findings))
        self.print_results()

        return len(self.drift_findings)


def main():
    tfstate_path = Path(__file__).parent.parent.parent / "terraform" / "terraform.tfstate"
    detector = DriftDetector(
        tfstate_path=str(tfstate_path),
        endpoint_url="http://localhost:4566"
    )
    drift_count = detector.run()
    sys.exit(1 if drift_count > 0 else 0)


if __name__ == "__main__":
    main()
