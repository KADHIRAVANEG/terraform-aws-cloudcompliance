#!/usr/bin/env python3
"""
CloudCompliance — GitHub PR Compliance Bot
Evaluates pull requests for SOC2/HIPAA/PCI-DSS compliance changes, detects regressions,
and posts rich visual feedback comments to GitHub Pull Requests.
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional, Tuple
from rich.console import Console

from cloudcompliance.report import (
    evaluate_controls,
    extract_resources,
    load_controls,
    load_tfstate,
)

console = Console()


def compute_state_hash(tfstate_data: dict) -> str:
    serialized = json.dumps(tfstate_data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]


def generate_pr_comment(
    current_results: dict,
    current_score: int,
    current_resources: list,
    base_results: Optional[dict] = None,
    base_score: Optional[int] = None,
    base_resources: Optional[list] = None,
    framework: str = "soc2",
    min_score: int = 80,
    fail_on_regression: bool = False,
    current_hash: str = "",
) -> Tuple[str, bool]:
    """
    Generate rich Markdown PR comment and determine pass/fail compliance status.
    Returns (comment_markdown, is_compliant).
    """
    fw_title = framework.upper()
    total_controls = len(current_results)
    current_pass = sum(1 for r in current_results.values() if r.get("status") == "PASS")

    # Evaluate pass/fail logic
    has_regression = (base_score is not None) and (current_score < base_score)
    meets_threshold = current_score >= min_score

    if fail_on_regression and has_regression:
        is_compliant = False
    else:
        is_compliant = meets_threshold

    # Badges
    score_badge = f"![Score](https://img.shields.io/badge/{fw_title}%20Score-{current_score}%25-{'brightgreen' if current_score >= 80 else 'yellow' if current_score >= 50 else 'red'})"
    status_badge = "![Status](https://img.shields.io/badge/PR%20Gate-PASSED-brightgreen)" if is_compliant else "![Status](https://img.shields.io/badge/PR%20Gate-BLOCKED-red)"

    lines = [
        f"## 🛡️ CloudCompliance PR Assessment — {fw_title}",
        "",
        f"{score_badge} &nbsp; {status_badge}",
        "",
    ]

    # Status callout banner
    if is_compliant:
        if base_score is not None and current_score > base_score:
            diff = current_score - base_score
            lines.append(f"> ✅ **PR PASSED:** Compliance score improved by **+{diff}%** (from {base_score}% to {current_score}%).")
        else:
            lines.append(f"> ✅ **PR PASSED:** Infrastructure satisfies the **{min_score}%** compliance gate ({current_score}% passing).")
    else:
        if has_regression:
            diff = base_score - current_score
            lines.append(f"> ❌ **COMPLIANCE REGRESSION DETECTED:** This pull request decreases {fw_title} score by **-{diff}%** (from {base_score}% down to {current_score}%).")
        else:
            lines.append(f"> ❌ **PR BLOCKED:** Compliance score of **{current_score}%** is below the required **{min_score}%** threshold.")

    lines.append("")
    lines.append("### 📊 Summary Metrics")
    lines.append("")
    lines.append("| Metric | PR Branch | Base Branch | Change |")
    lines.append("| :--- | :---: | :---: | :---: |")

    b_score_str = f"{base_score}%" if base_score is not None else "—"
    score_delta = f"{current_score - base_score:+d}%" if base_score is not None else "—"
    lines.append(f"| **{fw_title} Compliance Score** | **{current_score}%** | {b_score_str} | {score_delta} |")

    b_pass = sum(1 for r in base_results.values() if r.get("status") == "PASS") if base_results else None
    b_pass_str = f"{b_pass}/{len(base_results)}" if b_pass is not None else "—"
    pass_delta = f"{current_pass - b_pass:+d}" if b_pass is not None else "—"
    lines.append(f"| **Passing Controls** | **{current_pass}/{total_controls}** | {b_pass_str} | {pass_delta} |")

    b_res_cnt = len(base_resources) if base_resources is not None else None
    b_res_str = str(b_res_cnt) if b_res_cnt is not None else "—"
    res_delta = f"{len(current_resources) - b_res_cnt:+d}" if b_res_cnt is not None else "—"
    lines.append(f"| **Evaluated Resources** | **{len(current_resources)}** | {b_res_str} | {res_delta} |")

    lines.append("")
    lines.append("### 🔍 Control Coverage Details")
    lines.append("")
    lines.append("| Control | Title | Status | Evidence / Matched Resources |")
    lines.append("| :--- | :--- | :---: | :--- |")

    for cid, res in current_results.items():
        st = res.get("status")
        icon = "✅ PASS" if st == "PASS" else "⚠️ PARTIAL" if st == "PARTIAL" else "❌ FAIL"
        matched = ", ".join(res.get("matched", [])[:3]) or "*None*"

        # Note any status change compared to base
        change_note = ""
        if base_results and cid in base_results:
            old_st = base_results[cid].get("status")
            if old_st != st:
                change_note = f" *(was {old_st})*"

        lines.append(f"| `{cid}` | {res.get('title', '')} | **{icon}**{change_note} | {matched} |")

    # Missing resources remediation guide
    missing_items = [(cid, r) for cid, r in current_results.items() if r.get("missing")]
    if missing_items:
        lines.append("")
        lines.append("### 🛠️ Required Resources to Achieve Full Compliance")
        lines.append("")
        for cid, res in missing_items:
            missing_types = ", ".join(f"`{m}`" for m in res["missing"])
            lines.append(f"- **{cid}** ({res.get('title', '')}): Add {missing_types}")

    lines.append("")
    if current_hash:
        lines.append(f"**State SHA-256 Fingerprint:** `{current_hash}`  ")
    lines.append(f"*Automated compliance gate evaluated by [CloudCompliance](https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance)*")

    comment = "\n".join(lines)
    return comment, is_compliant


def post_github_pr_comment(
    comment_body: str,
    token: Optional[str] = None,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
) -> bool:
    """Post comment to GitHub PR via GitHub REST API."""
    import requests

    auth_token = token or os.getenv("GITHUB_TOKEN")
    target_repo = repo or os.getenv("GITHUB_REPOSITORY")

    if not pr_number:
        # Attempt to auto-detect from GitHub Actions environment
        ref = os.getenv("GITHUB_REF", "")
        if ref.startswith("refs/pull/") and "/merge" in ref:
            try:
                pr_number = int(ref.split("/")[2])
            except (IndexError, ValueError):
                pass

        if not pr_number and os.getenv("GITHUB_EVENT_PATH"):
            try:
                with open(os.environ["GITHUB_EVENT_PATH"]) as f:
                    event_data = json.load(f)
                    pr_number = event_data.get("pull_request", {}).get("number")
            except Exception:
                pass

    if not auth_token or not target_repo or not pr_number:
        console.print("[yellow]Notice: Missing GitHub credentials/context (token, repo, or PR number). Skipping live PR comment post.[/yellow]")
        return False

    url = f"https://api.github.com/repos/{target_repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CloudCompliance-Bot",
    }
    payload = {"body": comment_body}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        if response.status_code in (200, 201):
            console.print(f"[green]Successfully posted compliance review comment to {target_repo}#{pr_number}[/green]")
            return True
        else:
            console.print(f"[red]Failed to post comment to GitHub: HTTP {response.status_code} - {response.text}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]Error connecting to GitHub API: {e}[/red]")
        return False


def run_pr_check(
    current_state_path: str,
    base_state_path: Optional[str] = None,
    framework: str = "soc2",
    min_score: int = 80,
    fail_on_regression: bool = False,
    post_comment: bool = False,
    output_comment: Optional[str] = None,
    github_token: Optional[str] = None,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
) -> int:
    """Run end-to-end PR compliance check, returns exit code (0 = success, 1 = blocked)."""
    console.print(f"[bold cyan]CloudCompliance — Evaluating PR for {framework.upper()} Compliance[/bold cyan]")
    controls = load_controls(framework)

    # 1. Load current state
    console.print(f"[dim]Loading PR state: {current_state_path}[/dim]")
    current_state = load_tfstate(current_state_path)
    current_resources = extract_resources(current_state)
    current_results = evaluate_controls(current_resources, controls, provider="aws")
    current_pass = sum(1 for r in current_results.values() if r.get("status") == "PASS")
    current_score = int((current_pass / len(current_results)) * 100) if current_results else 0
    current_hash = compute_state_hash(current_state)

    # 2. Load optional base state
    base_results = None
    base_score = None
    base_resources = None
    if base_state_path and Path(base_state_path).exists():
        console.print(f"[dim]Loading Base state: {base_state_path}[/dim]")
        base_state = load_tfstate(base_state_path)
        base_resources = extract_resources(base_state)
        base_results = evaluate_controls(base_resources, controls, provider="aws")
        base_pass = sum(1 for r in base_results.values() if r.get("status") == "PASS")
        base_score = int((base_pass / len(base_results)) * 100) if base_results else 0

    comment_markdown, is_compliant = generate_pr_comment(
        current_results=current_results,
        current_score=current_score,
        current_resources=current_resources,
        base_results=base_results,
        base_score=base_score,
        base_resources=base_resources,
        framework=framework,
        min_score=min_score,
        fail_on_regression=fail_on_regression,
        current_hash=current_hash,
    )

    # 3. Output to file if requested
    if output_comment:
        out_p = Path(output_comment)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w") as f:
            f.write(comment_markdown)
        console.print(f"[dim]Saved PR comment markdown → {output_comment}[/dim]")

    # Also write to GitHub step summary if running inside GitHub Actions
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a") as f:
                f.write(f"\n\n{comment_markdown}\n")
        except Exception:
            pass

    # 4. Post to GitHub API if requested
    if post_comment:
        post_github_pr_comment(
            comment_body=comment_markdown,
            token=github_token,
            repo=repo,
            pr_number=pr_number,
        )

    # 5. Report summary to terminal
    console.print()
    if is_compliant:
        console.print(f"[bold green]✅ PR Compliance Check PASSED: {current_score}% (Threshold: {min_score}%)[/bold green]")
        return 0
    else:
        console.print(f"[bold red]❌ PR Compliance Check FAILED: {current_score}% (Threshold: {min_score}%)[/bold red]")
        return 1
