#!/usr/bin/env python3
"""
CloudCompliance — Auto-Remediation Engine
Automatically fixes low-risk drift and opens GitHub PRs for high-risk changes
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import boto3
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

load_dotenv(Path(__file__).parent.parent / ".env")

console = Console()

LOW_RISK = "LOW"
HIGH_RISK = "HIGH"
CRITICAL = "CRITICAL"

SEVERITY_RISK = {
    "MEDIUM": LOW_RISK,
    "HIGH": HIGH_RISK,
    "CRITICAL": CRITICAL,
}


class RemediationEngine:
    def __init__(self, endpoint_url: str = None, dry_run: bool = False):
        self.endpoint_url = endpoint_url or os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
        self.dry_run = dry_run
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_repo = os.getenv("GITHUB_REPO", "KADHIRAVANEG/cloudcompliance")
        self.actions_taken = []
        self.prs_opened = []

    def _client(self, service: str):
        kwargs = {"region_name": "us-east-1"}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return boto3.client(
            service,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            **kwargs
        )

    def load_drift_report(self) -> dict:
        drift_path = Path(__file__).parent.parent / "compliance" / "drift_report.json"
        if not drift_path.exists():
            console.print("[yellow]No drift report found. Run 'cloudcompliance drift' first.[/yellow]")
            sys.exit(0)
        with open(drift_path) as f:
            return json.load(f)

    def classify_risk(self, finding: dict) -> str:
        severity = finding.get("severity", "MEDIUM")
        return SEVERITY_RISK.get(severity, LOW_RISK)

    def remediate_unmanaged_bucket(self, finding: dict):
        bucket_name = finding["resource_id"]
        if self.dry_run:
            console.print(f"[dim][DRY RUN] Would tag unmanaged bucket: {bucket_name}[/dim]")
            return

        try:
            s3 = self._client("s3")
            s3.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={
                    "TagSet": [
                        {"Key": "ManagedBy", "Value": "CloudCompliance"},
                        {"Key": "RemediatedAt", "Value": datetime.now().isoformat()},
                        {"Key": "Status", "Value": "PendingTerraformImport"},
                    ]
                }
            )
            self.actions_taken.append({
                "action": "TAGGED_UNMANAGED_BUCKET",
                "resource": bucket_name,
                "timestamp": datetime.now().isoformat(),
                "details": "Tagged for Terraform import"
            })
            console.print(f"[green]✅ Tagged unmanaged bucket: {bucket_name}[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not tag bucket {bucket_name}: {e}[/yellow]")

    def get_default_branch_sha(self, headers: dict) -> tuple:
        """Returns (default_branch, sha) or raises exception."""
        repo_url = f"https://api.github.com/repos/{self.github_repo}"
        repo_resp = requests.get(repo_url, headers=headers, timeout=10)
        repo_resp.raise_for_status()
        default_branch = repo_resp.json().get("default_branch", "main")

        ref_url = f"https://api.github.com/repos/{self.github_repo}/git/refs/heads/{default_branch}"
        ref_resp = requests.get(ref_url, headers=headers, timeout=10)
        ref_resp.raise_for_status()
        sha = ref_resp.json()["object"]["sha"]
        return default_branch, sha

    def create_branch(self, headers: dict, branch_name: str, sha: str) -> bool:
        """Creates a new branch. Returns True on success."""
        branch_url = f"https://api.github.com/repos/{self.github_repo}/git/refs"
        resp = requests.post(branch_url, headers=headers, json={
            "ref": f"refs/heads/{branch_name}",
            "sha": sha
        }, timeout=10)
        if resp.status_code in [200, 201]:
            return True
        console.print(f"[dim]Branch creation: {resp.status_code} — {resp.text[:100]}[/dim]")
        return False

    def create_pr(self, headers: dict, branch_name: str, default_branch: str, finding: dict) -> str:
        """Creates a PR. Returns PR URL or empty string."""
        resource_id = finding["resource_id"]
        severity = finding["severity"]
        remediation = finding.get("remediation", "Run terraform apply")

        pr_body = f"""## 🚨 CloudCompliance Auto-Remediation

**Drift detected:** `{resource_id}`
**Type:** {finding.get('drift_type', 'UNKNOWN')}
**Severity:** {severity}

### What happened
{finding.get('description', 'Infrastructure drift detected outside of Terraform')}

### Recommended fix
```bash
{remediation}
```

### Action required
Review this change and merge if the remediation is correct.
After merging, run `make deploy` to restore the expected state.

---
*Auto-generated by CloudCompliance at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

        pr_url = f"https://api.github.com/repos/{self.github_repo}/pulls"
        pr_resp = requests.post(pr_url, headers=headers, json={
            "title": f"[CloudCompliance] Remediate {severity} drift: {resource_id}",
            "body": pr_body,
            "head": branch_name,
            "base": default_branch
        }, timeout=10)

        console.print(f"[dim]PR response: {pr_resp.status_code}[/dim]")

        if pr_resp.status_code in [200, 201]:
            return pr_resp.json().get("html_url", "")

        console.print(f"[dim]PR error: {pr_resp.text[:200]}[/dim]")
        return ""

    def open_github_pr(self, finding: dict):
        if not self.github_token:
            console.print("[yellow]Warning: GITHUB_TOKEN not set — skipping PR creation[/yellow]")
            return

        if self.dry_run:
            console.print(f"[dim][DRY RUN] Would open GitHub PR for: {finding['resource_id']}[/dim]")
            return

        resource_id = finding["resource_id"]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        branch_name = f"cloudcompliance/remediate-{resource_id.replace('/', '-').replace(' ', '-')}-{timestamp}"

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }

        try:
            default_branch, sha = self.get_default_branch_sha(headers)
            console.print(f"[dim]Default branch: {default_branch}, SHA: {sha[:8]}...[/dim]")

            branch_created = self.create_branch(headers, branch_name, sha)
            if not branch_created:
                console.print(f"[yellow]Warning: Could not create branch {branch_name}[/yellow]")
                return

            console.print(f"[dim]Branch created: {branch_name}[/dim]")

            # Add a remediation notes file as commit so PR can be created
            import base64
            remediation_note = f"""# CloudCompliance Remediation

**Resource:** {resource_id}
**Severity:** {finding.get('severity', 'HIGH')}
**Detected:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Issue
{finding.get('description', 'Infrastructure drift detected')}

## Fix
```bash
{finding.get('remediation', 'Run terraform apply')}
```
"""
            # Get existing file SHA if exists
            file_path = f"compliance/remediations/{resource_id.replace('/', '-')}-{timestamp}.md"
            file_url = f"https://api.github.com/repos/{self.github_repo}/contents/{file_path}"

            file_content = base64.b64encode(remediation_note.encode()).decode()
            file_resp = requests.put(file_url, headers=headers, json={
                "message": f"chore: remediation note for {resource_id}",
                "content": file_content,
                "branch": branch_name
            }, timeout=10)

            if file_resp.status_code not in [200, 201]:
                console.print(f"[yellow]Warning: Could not commit file — {file_resp.status_code}: {file_resp.text[:100]}[/yellow]")
                return

            console.print(f"[dim]Remediation file committed to branch[/dim]")

            pr_url_str = self.create_pr(headers, branch_name, default_branch, finding)

            if pr_url_str:
                self.prs_opened.append({
                    "resource": resource_id,
                    "pr_url": pr_url_str,
                    "severity": finding["severity"]
                })
                console.print(f"[cyan]📋 PR opened: {pr_url_str}[/cyan]")
                from cloudcompliance.notifications import notify_remediation
                notify_remediation(resource_id, pr_url_str, finding["severity"])
            else:
                console.print(f"[yellow]Warning: PR creation failed for {resource_id}[/yellow]")

        except requests.exceptions.HTTPError as e:
            console.print(f"[yellow]Warning: GitHub API error — {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: GitHub PR creation failed — {e}[/yellow]")

    def run(self):
        drift_report = self.load_drift_report()
        findings = drift_report.get("findings", [])

        if not findings:
            console.print(Panel.fit(
                "[bold green]✅ No drift found — nothing to remediate[/bold green]",
                border_style="green"
            ))
            return

        console.print()
        console.print(Panel.fit(
            "[bold cyan]CloudCompliance — Auto-Remediation Engine[/bold cyan]\n"
            f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
            f"[dim]{len(findings)} finding(s) to process[/dim]" +
            (" [yellow][DRY RUN][/yellow]" if self.dry_run else ""),
            border_style="cyan"
        ))
        console.print()

        low_risk = [f for f in findings if self.classify_risk(f) == LOW_RISK]
        high_risk = [f for f in findings if self.classify_risk(f) == HIGH_RISK]
        critical = [f for f in findings if self.classify_risk(f) == CRITICAL]

        if low_risk:
            console.print(f"[bold]Auto-fixing {len(low_risk)} low-risk finding(s)...[/bold]")
            for finding in low_risk:
                if finding["drift_type"] == "UNMANAGED":
                    self.remediate_unmanaged_bucket(finding)

        if high_risk:
            console.print(f"\n[bold]Opening GitHub PRs for {len(high_risk)} high-risk finding(s)...[/bold]")
            for finding in high_risk:
                console.print(f"[yellow]⚠️  {finding['severity']} — {finding['resource_id']}[/yellow]")
                self.open_github_pr(finding)

        if critical:
            console.print(f"\n[bold red]🔴 {len(critical)} CRITICAL finding(s) — immediate action required:[/bold red]")
            for finding in critical:
                console.print(f"  [red]{finding['resource_id']}[/red] — {finding['description']}")
                console.print(f"  [dim]Fix: {finding.get('remediation', 'Run terraform apply')}[/dim]")

        console.print()
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Action", width=25)
        table.add_column("Resource", width=35)
        table.add_column("Result", width=20)

        for action in self.actions_taken:
            table.add_row(
                action["action"],
                action["resource"],
                "[green]✅ Done[/green]"
            )

        for pr in self.prs_opened:
            table.add_row(
                "OPENED_PR",
                pr["resource"],
                "[cyan]PR created[/cyan]"
            )

        if self.actions_taken or self.prs_opened:
            console.print(table)

        log = {
            "generated_at": datetime.now().isoformat(),
            "dry_run": self.dry_run,
            "findings_processed": len(findings),
            "auto_fixed": len(self.actions_taken),
            "prs_opened": len(self.prs_opened),
            "actions": self.actions_taken,
            "pull_requests": self.prs_opened
        }
        log_path = Path(__file__).parent.parent / "compliance" / "remediation_log.json"
        with open(log_path, "w") as f:
            json.dump(log, f, indent=2)
        console.print(f"\n[dim]Remediation log saved → {log_path}[/dim]")
