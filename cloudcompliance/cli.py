#!/usr/bin/env python3
"""
CloudCompliance CLI Entrypoint
"""

import sys
import argparse
from pathlib import Path
from rich.console import Console
from cloudcompliance.report import (
    load_tfstate,
    extract_resources,
    evaluate_controls,
    print_report,
    get_default_tfstate_path,
    get_default_compliance_dir,
    load_controls,
)

console = Console()


def main():
    default_tfstate = str(get_default_tfstate_path())
    default_compliance = str(get_default_compliance_dir())

    parser = argparse.ArgumentParser(
        description="CloudCompliance — SOC2/HIPAA/PCI-DSS evidence, drift detection, history, AI assistant, CSPM live scanning, and PR guard"
    )
    parser.add_argument(
        "--tfstate",
        default=default_tfstate,
        help=f"Path or S3 URI to terraform.tfstate (default: {default_tfstate})"
    )
    parser.add_argument(
        "--output-dir",
        default=default_compliance,
        help=f"Directory to save compliance evidence and reports (default: {default_compliance})"
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        default=False,
        help="Generate signed executive auditor PDF report"
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        default=False,
        help="Generate OASIS SARIF v2.1.0 report for GitHub Security / Code Scanning"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "pdf"],
        default=None,
        help="Output report format (json, markdown, sarif, pdf)"
    )
    subparsers = parser.add_subparsers(dest="command")

    report_parser = subparsers.add_parser("report", help="Generate compliance evidence report")
    report_parser.add_argument(
        "--framework",
        default="soc2",
        choices=["soc2", "hipaa", "pcidss"],
        help="Compliance framework to evaluate against (default: soc2)"
    )
    report_parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "aws", "azure", "gcp", "all"],
        help="Cloud provider scope for controls evaluation (default: auto)"
    )
    report_parser.add_argument(
        "--rego",
        default=None,
        help="Path to a custom OPA Rego policy file to evaluate alongside standard controls"
    )
    report_parser.add_argument(
        "--pdf",
        action="store_true",
        default=False,
        help="Generate signed executive auditor PDF report"
    )
    report_parser.add_argument(
        "--sarif",
        action="store_true",
        default=False,
        help="Generate OASIS SARIF v2.1.0 report for GitHub Security / Code Scanning"
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "pdf"],
        default=None,
        help="Output report format (json, markdown, sarif, pdf)"
    )

    scan_parser = subparsers.add_parser("scan", help="Live agentless cloud posture scan (CSPM)")
    scan_parser.add_argument(
        "--live",
        action="store_true",
        default=True,
        help="Scan live AWS account directly via APIs without tfstate (default: True)"
    )
    scan_parser.add_argument(
        "--framework",
        default="soc2",
        choices=["soc2", "hipaa", "pcidss"],
        help="Compliance framework to evaluate against (default: soc2)"
    )
    scan_parser.add_argument(
        "--endpoint",
        default=None,
        help="AWS endpoint URL (for LocalStack or custom AWS endpoints)"
    )
    scan_parser.add_argument(
        "--region",
        default=None,
        help="Target AWS region (e.g. us-east-1)"
    )
    scan_parser.add_argument(
        "--all-regions",
        action="store_true",
        default=False,
        help="Scan all active AWS regions in the account"
    )
    scan_parser.add_argument(
        "--regions",
        default=None,
        help="Comma-separated list of target AWS regions (e.g. us-east-1,us-west-2)"
    )
    scan_parser.add_argument(
        "--pdf",
        action="store_true",
        default=False,
        help="Generate signed executive auditor PDF report"
    )
    scan_parser.add_argument(
        "--sarif",
        action="store_true",
        default=False,
        help="Generate OASIS SARIF v2.1.0 report for GitHub Security / Code Scanning"
    )

    init_parser = subparsers.add_parser("init", help="Interactive starter wizard to bootstrap compliant Terraform IaC")
    init_parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp"],
        default=None,
        help="Cloud provider (aws, azure, gcp)"
    )
    init_parser.add_argument(
        "--framework",
        choices=["soc2", "hipaa", "pcidss"],
        default=None,
        help="Primary compliance framework (soc2, hipaa, pcidss)"
    )
    init_parser.add_argument(
        "--env",
        choices=["dev", "staging", "prod"],
        default=None,
        help="Deployment environment tier (dev, staging, prod)"
    )
    init_parser.add_argument(
        "--project-name",
        default=None,
        help="Project or workload name"
    )
    init_parser.add_argument(
        "--region",
        default=None,
        help="Target AWS deployment region"
    )
    init_parser.add_argument(
        "--target-dir",
        default=None,
        help="Output directory to scaffold Terraform IaC files into"
    )
    init_parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help="Run without interactive prompts using defaults or provided flags"
    )

    pr_parser = subparsers.add_parser("pr-check", aliases=["pr-comment"], help="GitHub PR compliance guard and commenter")
    pr_parser.add_argument(
        "--current-state",
        default=None,
        help="Path or S3 URI to PR terraform.tfstate (defaults to --tfstate)"
    )
    pr_parser.add_argument(
        "--base-state",
        default=None,
        help="Path or S3 URI to base branch terraform.tfstate"
    )
    pr_parser.add_argument(
        "--framework",
        default="soc2",
        choices=["soc2", "hipaa", "pcidss"],
        help="Framework to evaluate (default: soc2)"
    )
    pr_parser.add_argument(
        "--min-score",
        type=int,
        default=80,
        help="Minimum required compliance score (default: 80)"
    )
    pr_parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Fail if PR compliance score drops below base branch"
    )
    pr_parser.add_argument(
        "--post-comment",
        action="store_true",
        help="Post evaluation markdown directly as a comment to GitHub PR"
    )
    pr_parser.add_argument(
        "--output-comment",
        default=None,
        help="Save markdown comment to specified file path"
    )
    pr_parser.add_argument(
        "--github-token",
        default=None,
        help="GitHub personal access token (or set GITHUB_TOKEN env var)"
    )
    pr_parser.add_argument(
        "--repo",
        default=None,
        help="GitHub repository in owner/repo format (or set GITHUB_REPOSITORY env var)"
    )
    pr_parser.add_argument(
        "--pr-number",
        type=int,
        default=None,
        help="Pull request number"
    )

    drift_parser = subparsers.add_parser("drift", help="Detect infrastructure drift")
    drift_parser.add_argument(
        "--endpoint",
        default=None,
        help="AWS endpoint URL (default: from AWS_ENDPOINT_URL, LOCALSTACK_ENDPOINT, or standard AWS)"
    )
    drift_parser.add_argument(
        "--demo",
        action="store_true",
        help="Demonstrate drift detection with sample infrastructure drift"
    )

    history_parser = subparsers.add_parser("history", help="Show compliance score history")
    history_parser.add_argument(
        "--framework",
        default=None,
        choices=["soc2", "hipaa", "pcidss"],
        help="Filter score history by compliance framework (default: all)"
    )
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

    schedule_parser = subparsers.add_parser("schedule", help="Run drift detection on a schedule")
    schedule_parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Check interval in minutes (default: 60)"
    )
    schedule_parser.add_argument(
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
    serve_parser.add_argument(
        "--token",
        default=None,
        help="Optional API bearer token to secure dashboard endpoints (or set CLOUDCOMPLIANCE_API_KEY)"
    )

    args = parser.parse_args()

    tfstate_path = args.tfstate
    output_dir = Path(args.output_dir)

    if args.command == "drift":
        from cloudcompliance.drift.detector import DriftDetector
        detector = DriftDetector(
            tfstate_path=tfstate_path,
            endpoint_url=args.endpoint,
            demo=getattr(args, "demo", False)
        )
        drift_count = detector.run()
        sys.exit(1 if drift_count > 0 else 0)

    elif args.command == "init":
        from cloudcompliance.wizard import run_wizard
        run_wizard(
            provider=args.provider,
            framework=args.framework,
            env=args.env,
            project_name=args.project_name,
            region=args.region,
            output_dir=Path(args.target_dir) if getattr(args, "target_dir", None) else None,
            non_interactive=getattr(args, "non_interactive", False),
        )
        sys.exit(0)

    elif args.command == "scan":
        from cloudcompliance.scanner import LiveAWSScanner
        regions_list = [r.strip() for r in args.regions.split(",")] if getattr(args, "regions", None) else None
        scanner = LiveAWSScanner(
            endpoint_url=args.endpoint,
            region=args.region,
            all_regions=getattr(args, "all_regions", False),
            regions=regions_list,
        )
        is_sarif = getattr(args, "sarif", False) or (getattr(args, "format", None) == "sarif")
        is_pdf = getattr(args, "pdf", False) or (getattr(args, "format", None) == "pdf")
        scanner.evaluate(
            framework=args.framework,
            output_dir=output_dir,
            pdf=is_pdf,
            sarif=is_sarif,
        )

    elif args.command in ("pr-check", "pr-comment"):
        from cloudcompliance.pr_bot import run_pr_check
        code = run_pr_check(
            current_state_path=args.current_state or tfstate_path,
            base_state_path=args.base_state,
            framework=args.framework,
            min_score=args.min_score,
            fail_on_regression=args.fail_on_regression,
            post_comment=args.post_comment,
            output_comment=args.output_comment,
            github_token=args.github_token,
            repo=args.repo,
            pr_number=args.pr_number,
        )
        sys.exit(code)

    elif args.command == "history":
        from cloudcompliance.history import show_history, export_history
        fw = getattr(args, "framework", None)
        if fw:
            show_history(limit=args.limit, framework=fw)
            if args.export:
                export_history(framework=fw)
        else:
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
            dry_run=args.dry_run,
            compliance_dir=output_dir
        )
        engine.run()

    elif args.command == "serve":
        from cloudcompliance.dashboard import serve
        serve(host=args.host, port=args.port, token=getattr(args, "token", None))

    elif args.command == "schedule":
        from cloudcompliance.scheduler import schedule
        schedule(
            interval_minutes=args.interval,
            endpoint_url=args.endpoint,
            tfstate_path=tfstate_path
        )

    else:
        # Default or 'report' command
        console.print(f"[dim]Reading state from: {tfstate_path}[/dim]")
        tfstate = load_tfstate(tfstate_path)
        resources = extract_resources(tfstate)

        framework = getattr(args, "framework", "soc2")
        provider = getattr(args, "provider", "auto")
        generate_pdf = getattr(args, "pdf", False)
        controls = load_controls(framework)

        results = evaluate_controls(resources, controls, provider=provider)

        if getattr(args, "rego", None):
            from cloudcompliance.opa import evaluate_rego
            console.print(f"[dim]Evaluating custom Rego policy: {args.rego}[/dim]")
            rego_results = evaluate_rego(tfstate_path, args.rego)
            if "violations" in rego_results and rego_results["violations"]:
                console.print(f"\n[red]🔴 Custom OPA Rego Violations Found: {len(rego_results['violations'])}[/red]")
                for v in rego_results["violations"]:
                    console.print(f"  - [red]{v}[/red]")
                console.print()
            elif "violations" in rego_results:
                console.print("[green]✅ Custom OPA Rego Policy: PASS[/green]\n")

        is_sarif = getattr(args, "sarif", False) or (getattr(args, "format", None) == "sarif")
        is_pdf = generate_pdf or (getattr(args, "format", None) == "pdf")

        print_report(
            results,
            resources,
            framework=framework,
            output_dir=output_dir,
            pdf=is_pdf,
            sarif=is_sarif,
            tfstate_path=tfstate_path,
        )


if __name__ == "__main__":
    main()
