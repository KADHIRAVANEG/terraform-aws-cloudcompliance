#!/usr/bin/env python3
"""
CloudCompliance — SOC2 Evidence Report Generator
Reads terraform.tfstate and maps resources to SOC2 Trust Service Criteria
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def get_default_compliance_dir() -> Path:
    """Return default compliance output directory, supporting Lambda /tmp."""
    if os.environ.get("LAMBDA_TASK_ROOT"):
        return Path("/tmp/compliance")
    if os.environ.get("COMPLIANCE_DIR"):
        return Path(os.environ["COMPLIANCE_DIR"])
    return Path.cwd() / "compliance"


def get_default_tfstate_path() -> Path:
    """Resolve default tfstate location based on current working directory."""
    candidates = [
        Path.cwd() / "terraform" / "terraform.tfstate",
        Path.cwd() / "terraform.tfstate",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def load_controls(framework: str = "soc2") -> dict:
    controls_path = Path(__file__).parent / "controls.json"
    with open(controls_path) as f:
        all_frameworks = json.load(f)
        if framework not in all_frameworks:
            console.print(f"[red]Error: Framework '{framework}' not found in controls.json[/red]")
            sys.exit(1)
        return all_frameworks[framework]


def load_tfstate(path: str) -> dict:
    if path.startswith("s3://"):
        import boto3
        s3 = boto3.client("s3")
        path_without_scheme = path[5:]
        bucket_name = path_without_scheme.split("/")[0]
        key = "/".join(path_without_scheme.split("/")[1:])
        try:
            response = s3.get_object(Bucket=bucket_name, Key=key)
            return json.loads(response['Body'].read().decode('utf-8'))
        except Exception as e:
            console.print(f"[red]Error fetching tfstate from S3: {e}[/red]")
            sys.exit(1)

    tfstate_path = Path(path)
    if not tfstate_path.exists():
        console.print(f"[red]Error: tfstate not found at {path}[/red]")
        sys.exit(1)
    with open(tfstate_path) as f:
        return json.load(f)


def extract_resources(tfstate: dict) -> list:
    resources = []
    for resource in tfstate.get("resources", []):
        instances = resource.get("instances", [])
        attrs = instances[0].get("attributes", {}) if instances else {}
        resources.append({
            "type": resource.get("type"),
            "name": resource.get("name"),
            "module": resource.get("module", "root"),
            "attributes": attrs,
            "tags": attrs.get("tags") or {},
        })
    return resources


def get_resource_provider(res_type: str) -> str:
    if not res_type:
        return "other"
    if res_type.startswith("aws_"):
        return "aws"
    if res_type.startswith("azurerm_") or res_type.startswith("azure_"):
        return "azure"
    if res_type.startswith("google_") or res_type.startswith("gcp_"):
        return "gcp"
    return "other"


def evaluate_deep_attributes(resources: list) -> dict:
    """
    Inspect individual resource attributes for security violations and compliance gaps.
    Evaluates individual configurations rather than mere resource type existence.
    """
    violations_by_control = {}

    def add_violation(control_id: str, message: str):
        violations_by_control.setdefault(control_id, []).append(message)

    for r in resources:
        res_type = r.get("type", "")
        res_name = r.get("name", "unnamed")
        attrs = r.get("attributes") or {}

        # 1. CC6.1 Logical Access / Boundary Exposure
        if res_type == "aws_security_group":
            ingress_rules = attrs.get("ingress", []) or []
            for rule in ingress_rules:
                cidrs = rule.get("cidr_blocks", []) or []
                if "0.0.0.0/0" in cidrs:
                    from_port = rule.get("from_port")
                    to_port = rule.get("to_port")
                    if from_port in (22, 3389) or to_port in (22, 3389):
                        add_violation("CC6.1", f"Security group '{res_name}' allows unrestricted ingress on management port ({from_port}-{to_port}) from 0.0.0.0/0")
                    elif from_port in (3306, 5432, 27017, 6379):
                        add_violation("CC6.1", f"Security group '{res_name}' allows unrestricted database ingress ({from_port}) from 0.0.0.0/0")

        if res_type == "aws_db_instance":
            if attrs.get("publicly_accessible") is True:
                add_violation("CC6.1", f"RDS database '{res_name}' is configured as publicly accessible")

        # 2. CC6.7 Encryption at Rest & Key Management
        if res_type == "aws_kms_key":
            if attrs.get("enable_key_rotation") is False:
                add_violation("CC6.7", f"KMS key '{res_name}' has automatic cryptographic rotation disabled")

        if res_type == "aws_db_instance":
            if attrs.get("storage_encrypted") is False:
                add_violation("CC6.7", f"RDS database '{res_name}' has storage encryption disabled")

        if res_type == "aws_ebs_volume":
            if attrs.get("encrypted") is False:
                add_violation("CC6.7", f"EBS volume '{res_name}' is unencrypted at rest")

        # 3. A1.1 Availability & Automated Backups
        if res_type == "aws_db_instance":
            retention = attrs.get("backup_retention_period", 1)
            if retention is not None and int(retention) == 0:
                add_violation("A1.1", f"RDS database '{res_name}' has automated backup retention set to 0 days (disabled)")

    return violations_by_control


def evaluate_controls(resources: list, controls: dict, provider: str = "auto") -> dict:
    found_types = set(r["type"] for r in resources if r.get("type"))
    deep_violations = evaluate_deep_attributes(resources)

    # Determine which cloud providers to evaluate
    if provider and provider != "auto" and provider != "all":
        target_providers = {provider.lower()}
    elif provider == "all":
        target_providers = {"aws", "azure", "gcp", "other"}
    else:
        # Auto-detect from resources present
        detected = set(get_resource_provider(r["type"]) for r in resources if r.get("type"))
        valid_detected = {p for p in detected if p != "other"}
        target_providers = valid_detected if valid_detected else {"aws"}

    results = {}
    for control_id, control in controls.items():
        # Filter control resource requirements to the target provider(s)
        control_resources = control.get("resources", [])
        filtered_resources = [
            t for t in control_resources
            if get_resource_provider(t) in target_providers or get_resource_provider(t) == "other"
        ]
        # Fallback if control defines no resources for target provider
        effective_resources = filtered_resources if filtered_resources else control_resources

        matched = [t for t in effective_resources if t in found_types]
        missing = [t for t in effective_resources if t not in found_types]
        violations = deep_violations.get(control_id, [])

        if len(matched) == len(effective_resources) and len(effective_resources) > 0:
            status = "PASS" if not violations else "PARTIAL"
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
            "violations": violations,
        }
    return results


def save_markdown(results: dict, resources: list, score: int, pass_count: int, framework: str = "soc2", output_dir: Path = None):
    out_dir = Path(output_dir) if output_dir else get_default_compliance_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{framework}_compliance_report.md"
    with open(md_path, "w") as f:
        f.write(f"# CloudCompliance — {framework.upper()} Evidence Report\n\n")
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
        f.write(f"{framework.upper()} Compliance Score: **{score}%** ({pass_count}/{len(results)} controls passing)\n\n")
        f.write("## Standards Referenced\n\n")
        f.write("- AICPA SOC2 Trust Services Criteria 2017\n")
        f.write("- CIS AWS Foundations Benchmark v2.0\n")
        f.write("- NIST SP 800-53 Rev 5\n")
    console.print(f"[dim]Markdown report → {md_path}[/dim]")

    if framework == "soc2":
        legacy_md = out_dir / "compliance_report.md"
        with open(legacy_md, "w") as f:
            with open(md_path) as src:
                f.write(src.read())


def print_report(results: dict, resources: list, output_path: Path = None, framework: str = "soc2", output_dir: Path = None, pdf: bool = False, tfstate_path: str = None, sarif: bool = False):
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]CloudCompliance — {framework.upper()} Evidence Report[/bold cyan]\n"
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

    score = int((pass_count / len(results)) * 100) if results else 0
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print(Panel.fit(
        f"[bold {color}]{framework.upper()} Compliance Score: {score}% ({pass_count}/{len(results)} controls passing)[/bold {color}]",
        border_style=color
    ))

    missing_any = [(cid, r) for cid, r in results.items() if r["missing"]]
    if missing_any:
        console.print()
        console.print("[bold yellow]Resources to add for full compliance:[/bold yellow]")
        for control_id, result in missing_any:
            for m in result["missing"]:
                console.print(f"  [dim]{control_id}[/dim] → [red]{m}[/red]")

    violations_any = [(cid, r) for cid, r in results.items() if r.get("violations")]
    if violations_any:
        console.print()
        console.print("[bold red]🚨 Deep Resource Configuration Violations Detected:[/bold red]")
        for control_id, result in violations_any:
            for v in result["violations"]:
                console.print(f"  [dim]{control_id}[/dim] → [red]{v}[/red]")

    output = {
        "generated_at": datetime.now().isoformat(),
        "total_resources": len(resources),
        "compliance_score": score,
        "controls": results,
    }

    out_dir = Path(output_dir) if output_dir else get_default_compliance_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        target_output_path = out_dir / f"{framework}_compliance_report.json"
    else:
        target_output_path = Path(output_path)
        target_output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_output_path, "w") as f:
        json.dump(output, f, indent=2)
    console.print()
    console.print(f"[dim]Evidence saved → {target_output_path}[/dim]")

    if framework == "soc2" and output_path is None:
        legacy_path = out_dir / "compliance_report.json"
        with open(legacy_path, "w") as f:
            json.dump(output, f, indent=2)

    save_markdown(results, resources, score, pass_count, framework, output_dir=out_dir)

    if pdf:
        try:
            from cloudcompliance.pdf_report import generate_pdf_report
            pdf_path = out_dir / f"{framework}_compliance_report.pdf"
            generate_pdf_report(
                results=results,
                resources=resources,
                score=score,
                pass_count=pass_count,
                framework=framework,
                output_path=pdf_path,
                tfstate_path=tfstate_path,
            )
            console.print(f"[green]Executive PDF report → {pdf_path}[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate PDF report: {e}[/yellow]")

    if sarif:
        try:
            from cloudcompliance.sarif import generate_sarif, save_sarif
            sarif_data = generate_sarif(results, framework=framework)
            sarif_path = out_dir / f"{framework}_compliance_report.sarif"
            save_sarif(sarif_data, sarif_path)
            console.print(f"[green]SARIF report → {sarif_path}[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate SARIF report: {e}[/yellow]")

    from cloudcompliance.history import save_score
    save_score(target_output_path, framework=framework)
    # Multi-channel notification
    from cloudcompliance.notifications import notify_compliance_score
    notify_compliance_score(score, pass_count, len(results), len(resources), framework=framework)


def run(tfstate_path: str = None, output_path: str = None, framework: str = "soc2", provider: str = "auto", output_dir: Path = None, pdf: bool = False, sarif: bool = False):
    resolved_state = Path(tfstate_path) if tfstate_path else get_default_tfstate_path()
    console.print(f"[dim]Reading state from: {resolved_state}[/dim]")
    tfstate = load_tfstate(str(resolved_state))
    resources = extract_resources(tfstate)
    controls = load_controls(framework)
    results = evaluate_controls(resources, controls, provider=provider)
    print_report(results, resources, output_path=Path(output_path) if output_path else None, framework=framework, output_dir=output_dir, pdf=pdf, tfstate_path=str(resolved_state), sarif=sarif)


def main():
    """Backward compatibility entry point for cloudcompliance <= 1.6.0."""
    from cloudcompliance.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    main()
