#!/usr/bin/env python3
"""
CloudCompliance — SOC2 Evidence Report Generator
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SOC2_CONTROLS = {
    "CC6.1": {
        "title": "Logical Access — Network Isolation",
        "description": "Restrict logical access via private networking and ACLs",
        "resources": ["aws_vpc", "aws_subnet", "aws_default_security_group"],
    },
    "CC6.2": {
        "title": "Logical Access — Authentication Controls",
        "description": "Enforce strong authentication, password policy, least privilege",
        "resources": ["aws_iam_account_password_policy", "aws_iam_role", "aws_iam_policy", "aws_sns_topic"],
    },
    "CC6.7": {
        "title": "Encryption — Data Protection",
        "description": "Encrypt data at rest and in transit using KMS and HTTPS",
        "resources": ["aws_kms_key", "aws_kms_alias", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy"],
    },
    "CC7.1": {
        "title": "Threat Detection — Continuous Monitoring",
        "description": "Monitor for anomalous activity and compliance drift",
        "resources": ["aws_cloudwatch_metric_alarm", "aws_config_configuration_recorder", "aws_config_config_rule"],
    },
    "CC7.2": {
        "title": "Audit Logging — Tamper-evident Records",
        "description": "Log all activity with integrity validation and retention",
        "resources": ["aws_s3_bucket_versioning", "aws_s3_bucket_public_access_block", "aws_config_delivery_channel", "aws_flow_log", "aws_cloudwatch_log_group"],
    },
    "CC6.6": {
        "title": "Logical Access — Transmission Protection",
        "description": "Protect data in transit — HTTPS only, deny plaintext",
        "resources": ["aws_s3_bucket_policy"],
    },
    "CC8.1": {
        "title": "Change Management — IaC Controlled",
        "description": "All infrastructure changes via version-controlled IaC",
        "resources": ["aws_iam_role", "aws_config_configuration_recorder_status"],
    },
}


def load_tfstate(path: str) -> dict:
    tfstate_path = Path(path)
    if not tfstate_path.exists():
        console.print(f"[red]Error: tfstate not found at {path}[/red]")
        sys.exit(1)
    with open(tfstate_path) as f:
        return json.load(f)


def extract_resources(tfstate: dict) -> list:
    resources = []
    for resource in tfstate.get("resources", []):
        resources.append({
            "type": resource.get("type"),
            "name": resource.get("name"),
            "module": resource.get("module", "root"),
            "tags": resource.get("instances", [{}])[0]
                          .get("attributes", {})
                          .get("tags", {}),
        })
    return resources


def evaluate_controls(resources: list) -> dict:
    found_types = set(r["type"] for r in resources)
    results = {}
    for control_id, control in SOC2_CONTROLS.items():
        matched = [t for t in control["resources"] if t in found_types]
        missing = [t for t in control["resources"] if t not in found_types]
        if len(matched) == len(control["resources"]):
            status = "PASS"
        elif len(matched) > 0:
            status = "PARTIAL"
        else:
            status = "FAIL"
        results[control_id] = {
            "title": control["title"],
            "description": control["description"],
            "status": status,
            "matched": matched,
            "missing": missing,
        }
    return results


def print_report(results: dict, resources: list, output_path: Path = None):
    console.print()
    console.print(Panel.fit(
        "[bold cyan]CloudCompliance — SOC2 Evidence Report[/bold cyan]\n"
        f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
        f"[dim]Total resources provisioned: {len(resources)}[/dim]",
        border_style="cyan"
    ))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Control", style="cyan", width=8)
    table.add_column("Title", width=35)
    table.add_column("Status", width=10)
    table.add_column("Matched Resources", width=40)

    pass_count = 0
    for control_id, result in results.items():
        status = result["status"]
        if status == "PASS":
            status_str = "[green]✅ PASS[/green]"
            pass_count += 1
        elif status == "PARTIAL":
            status_str = "[yellow]⚠️  PARTIAL[/yellow]"
        else:
            status_str = "[red]❌ FAIL[/red]"
        matched_str = ", ".join(result["matched"]) if result["matched"] else "[dim]none[/dim]"
        table.add_row(control_id, result["title"], status_str, matched_str)

    console.print(table)
    console.print()

    score = int((pass_count / len(results)) * 100)
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print(Panel.fit(
        f"[bold {color}]SOC2 Compliance Score: {score}% ({pass_count}/{len(results)} controls passing)[/bold {color}]",
        border_style=color
    ))

    output = {
        "generated_at": datetime.now().isoformat(),
        "total_resources": len(resources),
        "compliance_score": score,
        "controls": results,
    }

    if output_path is None:
        output_path = Path(__file__).parent.parent / "compliance" / "compliance_report.json"

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    console.print()
    console.print(f"[dim]Evidence saved → {output_path}[/dim]")


def run(tfstate_path: str = None, output_path: str = None):
    if tfstate_path is None:
        tfstate_path = Path(__file__).parent.parent / "terraform" / "terraform.tfstate"
    console.print(f"[dim]Reading state from: {tfstate_path}[/dim]")
    tfstate = load_tfstate(str(tfstate_path))
    resources = extract_resources(tfstate)
    results = evaluate_controls(resources)
    print_report(results, resources, Path(output_path) if output_path else None)

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CloudCompliance — SOC2 evidence and drift detection"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("report", help="Generate SOC2 compliance evidence report")

    drift_parser = subparsers.add_parser("drift", help="Detect infrastructure drift")
    drift_parser.add_argument(
        "--endpoint",
        default="http://localhost:4566",
        help="AWS endpoint URL (default: LocalStack)"
    )

    args = parser.parse_args()

    tfstate_path = Path(__file__).parent.parent / "terraform" / "terraform.tfstate"

    if args.command == "drift":
        from cloudcompliance.drift.detector import DriftDetector
        detector = DriftDetector(
            tfstate_path=str(tfstate_path),
            endpoint_url=args.endpoint
        )
        drift_count = detector.run()
        sys.exit(1 if drift_count > 0 else 0)
    else:
        console.print(f"[dim]Reading state from: {tfstate_path}[/dim]")
        tfstate = load_tfstate(str(tfstate_path))
        resources = extract_resources(tfstate)
        results = evaluate_controls(resources)
        print_report(results, resources)
