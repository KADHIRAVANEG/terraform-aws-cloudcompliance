#!/usr/bin/env python3
"""
CloudCompliance — SOC2 Evidence Report Generator
Reads terraform.tfstate and maps resources to SOC2 Trust Service Criteria
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
    "CC6.3": {
        "title": "Logical Access — Access Revocation",
        "description": "Detect and alert on overly permissive IAM and resource policies",
        "resources": ["aws_iam_role_policy", "aws_cloudwatch_metric_alarm"],
    },
    "CC6.6": {
        "title": "Logical Access — Transmission Protection",
        "description": "Protect data in transit — HTTPS only, deny plaintext",
        "resources": ["aws_s3_bucket_policy"],
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
    "CC7.3": {
        "title": "Incident Response — Security Event Detection",
        "description": "Detect and alert on unauthorized access and security incidents",
        "resources": ["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_log_group"],
    },
    "CC8.1": {
        "title": "Change Management — IaC Controlled",
        "description": "All infrastructure changes via version-controlled IaC",
        "resources": ["aws_iam_role", "aws_config_configuration_recorder_status"],
    },
    "A1.1": {
        "title": "Availability — Backup and Retention",
        "description": "Ensure data availability via versioning, retention, and backup policies",
        "resources": ["aws_s3_bucket_versioning", "aws_iam_role_policy_attachment"],
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


def save_markdown(results: dict, resources: list, score: int, pass_count: int):
    md_path = Path(__file__).parent.parent / "compliance" / "compliance_report.md"
    with open(md_path, "w") as f:
        f.write("# CloudCompliance — SOC2 Evidence Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Total resources provisioned:** {len(resources)}  \n")
        f.write(f"**Compliance score:** {score}% ({pass_count}/{len(results)} controls passing)\n\n")
        f.write("## Control Coverage\n\n")
        f.write("| Control | Title | Status | Matched Resources |\n")
        f.write("|---------|-------|--------|-------------------|\n")
        for control_id, result in results.items():
            if result["status"] == "PASS":
                status_md = "✅ PASS"
            elif result["status"] == "PARTIAL":
                status_md = "⚠️ PARTIAL"
            else:
                status_md = "❌ FAIL"
            matched = ", ".join(result["matched"][:3]) if result["matched"] else "none"
            f.write(f"| {control_id} | {result['title']} | {status_md} | {matched} |\n")
        f.write(f"\n## Summary\n\n")
        f.write(f"SOC2 Compliance Score: **{score}%** ({pass_count}/{len(results)} controls passing)\n\n")
        f.write("## Standards Referenced\n\n")
        f.write("- AICPA SOC2 Trust Services Criteria 2017\n")
        f.write("- CIS AWS Foundations Benchmark v2.0\n")
        f.write("- NIST SP 800-53 Rev 5\n")
    console.print(f"[dim]Markdown report → {md_path}[/dim]")


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

    missing_any = [(cid, r) for cid, r in results.items() if r["missing"]]
    if missing_any:
        console.print()
        console.print("[bold yellow]Resources to add for full compliance:[/bold yellow]")
        for control_id, result in missing_any:
            for m in result["missing"]:
                console.print(f"  [dim]{control_id}[/dim] → [red]{m}[/red]")

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

    save_markdown(results, resources, score, pass_count)

    from cloudcompliance.history import save_score
    save_score(output_path)


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
        description="CloudCompliance — SOC2 evidence, drift detection, history, AI assistant and auto-remediation"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("report", help="Generate SOC2 compliance evidence report")

    drift_parser = subparsers.add_parser("drift", help="Detect infrastructure drift")
    drift_parser.add_argument(
        "--endpoint",
        default="http://localhost:4566",
        help="AWS endpoint URL (default: LocalStack)"
    )

    history_parser = subparsers.add_parser("history", help="Show compliance score history")
    history_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of entries to show (default: 10)"
    )
    history_parser.add_argument(
        "--export",
        action="store_true",
        help="Export history as JSON for auditors"
    )

    ask_parser = subparsers.add_parser("ask", help="Ask AI about your compliance state")
    ask_parser.add_argument("question", help="Your compliance question")
    ask_parser.add_argument(
        "--api-key",
        default=None,
        help="NVIDIA NIM API key (or set NVIDIA_API_KEY env var)"
    )

    remediate_parser = subparsers.add_parser("remediate", help="Auto-remediate drift findings")
    remediate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    remediate_parser.add_argument(
        "--endpoint",
        default=None,
        help="AWS endpoint URL"
    )
    
    serve_parser = subparsers.add_parser("serve", help="Start live compliance dashboard")
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to run dashboard on (default: 8080)"
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)"
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

    elif args.command == "history":
        from cloudcompliance.history import show_history, export_history
        show_history(limit=args.limit)
        if args.export:
            export_history()

    elif args.command == "ask":
        from cloudcompliance.assistant import main as ask_main
        ask_main(args.question, args.api_key)

    elif args.command == "remediate":
        from cloudcompliance.remediation import RemediationEngine
        engine = RemediationEngine(
            endpoint_url=args.endpoint,
            dry_run=args.dry_run
        )
        engine.run()

    elif args.command == "serve":
        from cloudcompliance.dashboard import serve
        serve(host=args.host, port=args.port)

    else:
        console.print(f"[dim]Reading state from: {tfstate_path}[/dim]")
        tfstate = load_tfstate(str(tfstate_path))
        resources = extract_resources(tfstate)
        results = evaluate_controls(resources)
        print_report(results, resources)


if __name__ == "__main__":
    main()
