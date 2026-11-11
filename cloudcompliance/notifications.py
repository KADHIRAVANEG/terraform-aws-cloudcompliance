#!/usr/bin/env python3
"""
CloudCompliance — Multi-Channel Alerting & Webhooks
Dispatches real-time compliance score regressions, drift alerts, and auto-remediation
events across Slack, Microsoft Teams, Discord, and Generic/PagerDuty webhooks.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


def get_webhooks() -> Dict[str, str]:
    """Retrieve all configured webhook endpoints from environment."""
    return {
        "slack": os.getenv("SLACK_WEBHOOK_URL", ""),
        "teams": os.getenv("TEAMS_WEBHOOK_URL", ""),
        "discord": os.getenv("DISCORD_WEBHOOK_URL", ""),
        "generic": (
            os.getenv("GENERIC_WEBHOOK_URL")
            or os.getenv("COMPLIANCE_WEBHOOK_URL")
            or os.getenv("PAGERDUTY_WEBHOOK_URL", "")
        ),
    }


def send_slack(payload: dict) -> bool:
    webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook:
        return False
    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def send_teams(title: str, text: str, color: str = "1D9E75", fields: Optional[List[Dict[str, str]]] = None, url: Optional[str] = None) -> bool:
    """Send alert formatted as an Office 365 Connector MessageCard to Microsoft Teams."""
    webhook = os.getenv("TEAMS_WEBHOOK_URL", "")
    if not webhook:
        return False

    facts = [{"name": f["title"], "value": f["value"]} for f in (fields or [])]
    theme_color = color.lstrip("#")

    payload: Dict[str, Any] = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": theme_color,
        "title": title,
        "text": text,
        "sections": [{"facts": facts}] if facts else [],
    }
    if url:
        payload["potentialAction"] = [
            {
                "@type": "OpenURI",
                "name": "View in CloudCompliance",
                "targets": [{"os": "default", "uri": url}],
            }
        ]

    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def send_discord(title: str, description: str, color_hex: str = "#1D9E75", fields: Optional[List[Dict[str, str]]] = None, url: Optional[str] = None) -> bool:
    """Send alert formatted as an embedded message to Discord webhook."""
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
    if not webhook:
        return False

    # Convert hex color string to integer
    try:
        color_int = int(color_hex.lstrip("#"), 16)
    except ValueError:
        color_int = 0x1D9E75

    embed_fields = [
        {"name": f["title"], "value": f["value"], "inline": f.get("short", False)}
        for f in (fields or [])
    ]

    embed = {
        "title": title,
        "description": description,
        "color": color_int,
        "fields": embed_fields,
        "footer": {"text": "CloudCompliance DevSecOps Guard"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if url:
        embed["url"] = url

    payload = {
        "username": "CloudCompliance Bot",
        "avatar_url": "https://raw.githubusercontent.com/KADHIRAVANEG/terraform-aws-cloudcompliance/main/docs/favicon.ico",
        "embeds": [embed],
    }

    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def send_generic_webhook(event_type: str, data: Dict[str, Any], severity: str = "INFO") -> bool:
    """Send a structured JSON alert to a generic endpoint or PagerDuty event API."""
    webhook = (
        os.getenv("GENERIC_WEBHOOK_URL")
        or os.getenv("COMPLIANCE_WEBHOOK_URL")
        or os.getenv("PAGERDUTY_WEBHOOK_URL", "")
    )
    if not webhook:
        return False

    payload = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "source": "cloudcompliance",
        "details": data,
    }

    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code in (200, 201, 202, 204)
    except Exception:
        return False


def dispatch_alert(
    title: str,
    summary: str,
    color: str = "#1D9E75",
    fields: Optional[List[Dict[str, str]]] = None,
    severity: str = "INFO",
    raw_data: Optional[Dict[str, Any]] = None,
    url: Optional[str] = None,
):
    """Broadcast an alert to all configured notification channels."""
    # 1. Slack
    slack_payload = {
        "attachments": [
            {
                "color": color,
                "pretext": title,
                "text": summary,
                "fields": fields or [],
                "footer": "CloudCompliance Alerting",
                "footer_icon": "https://raw.githubusercontent.com/KADHIRAVANEG/terraform-aws-cloudcompliance/main/docs/favicon.ico",
                "ts": int(datetime.now().timestamp()),
            }
        ]
    }
    send_slack(slack_payload)

    # 2. Microsoft Teams
    send_teams(title=title, text=summary, color=color, fields=fields, url=url)

    # 3. Discord
    send_discord(title=title, description=summary, color_hex=color, fields=fields, url=url)

    # 4. Generic Webhook / PagerDuty
    send_generic_webhook(
        event_type=title,
        data=raw_data or {"title": title, "summary": summary, "fields": fields},
        severity=severity,
    )


def notify_drift(findings: list, drift_count: int):
    if not findings:
        return

    color = "#ef4444" if any(f.get("severity") == "CRITICAL" for f in findings) else "#f59e0b"
    title = f":warning: CloudCompliance — {drift_count} Drift Finding(s) Detected"
    summary = "Infrastructure discrepancy detected between live AWS environment and Terraform state."

    fields = [
        {
            "title": f["resource_id"],
            "value": f"{f.get('severity', 'HIGH')} — {f.get('drift_type', 'DRIFT')}: {f.get('description', '')[:80]}",
            "short": False,
        }
        for f in findings[:5]
    ]

    dispatch_alert(
        title=title,
        summary=summary,
        color=color,
        fields=fields,
        severity="HIGH",
        raw_data={"drift_count": drift_count, "findings": findings},
    )


def notify_remediation(resource: str, pr_url: str, severity: str):
    title = ":white_check_mark: CloudCompliance — Auto-Remediation PR Opened"
    summary = f"Automated pull request opened to import or remediate unmanaged resource '{resource}'."
    fields = [
        {"title": "Resource", "value": resource, "short": True},
        {"title": "Severity", "value": severity, "short": True},
        {"title": "Pull Request", "value": pr_url, "short": False},
    ]

    dispatch_alert(
        title=title,
        summary=summary,
        color="#1D9E75",
        fields=fields,
        severity="INFO",
        url=pr_url,
        raw_data={"resource": resource, "pr_url": pr_url, "severity": severity},
    )


def notify_compliance_score(score: int, passing: int, total: int, resources: int, framework: str = "soc2"):
    color = "#1D9E75" if score >= 80 else "#f59e0b" if score >= 50 else "#ef4444"
    icon = ":white_check_mark:" if score >= 80 else ":warning:" if score >= 50 else ":x:"
    fw_title = framework.upper()

    title = f"{icon} CloudCompliance — {fw_title} Compliance Report"
    summary = f"Compliance evaluation completed for {resources} provisioned resources."
    fields = [
        {"title": f"{fw_title} Score", "value": f"{score}% ({passing}/{total} controls passing)", "short": True},
        {"title": "Total Resources", "value": str(resources), "short": True},
    ]

    dispatch_alert(
        title=title,
        summary=summary,
        color=color,
        fields=fields,
        severity="INFO" if score >= 80 else "WARNING",
        raw_data={"framework": framework, "score": score, "passing": passing, "total": total, "resources": resources},
    )


def notify_no_drift():
    title = ":white_check_mark: CloudCompliance — Infrastructure In Sync"
    summary = "Live infrastructure perfectly matches Terraform state. No drift detected."

    dispatch_alert(
        title=title,
        summary=summary,
        color="#1D9E75",
        severity="INFO",
        raw_data={"drift_count": 0, "status": "clean"},
    )
