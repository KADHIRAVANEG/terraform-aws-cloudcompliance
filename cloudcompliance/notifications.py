#!/usr/bin/env python3
"""
CloudCompliance — Slack Notifications
Sends drift alerts and remediation notifications to Slack
"""

import json
import os
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")


def get_webhook() -> str:
    return os.getenv("SLACK_WEBHOOK_URL", "")


def send_slack(payload: dict) -> bool:
    webhook = get_webhook()
    if not webhook:
        return False
    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def notify_drift(findings: list, drift_count: int):
    if not findings:
        return

    webhook = get_webhook()
    if not webhook:
        return

    color = "#f59e0b" if any(f["severity"] == "HIGH" for f in findings) else "#ef4444"
    if any(f["severity"] == "CRITICAL" for f in findings):
        color = "#ef4444"

    fields = [
        {
            "title": f["resource_id"],
            "value": f"{f['severity']} — {f['drift_type']}: {f['description'][:80]}",
            "short": False
        }
        for f in findings[:5]
    ]

    payload = {
        "attachments": [
            {
                "color": color,
                "pretext": f":warning: *CloudCompliance — {drift_count} Drift Finding(s) Detected*",
                "fields": fields,
                "footer": "CloudCompliance Drift Detection",
                "footer_icon": "https://raw.githubusercontent.com/KADHIRAVANEG/cloudcompliance/main/docs/favicon.ico",
                "ts": int(datetime.now().timestamp()),
                "actions": [
                    {
                        "type": "button",
                        "text": "Run Remediation",
                        "style": "danger",
                        "value": "remediate"
                    }
                ]
            }
        ]
    }

    sent = send_slack(payload)
    if sent:
        print("[dim]Slack notification sent[/dim]")


def notify_remediation(resource: str, pr_url: str, severity: str):
    webhook = get_webhook()
    if not webhook:
        return

    payload = {
        "attachments": [
            {
                "color": "#1D9E75",
                "pretext": ":white_check_mark: *CloudCompliance — Auto-Remediation PR Opened*",
                "fields": [
                    {
                        "title": "Resource",
                        "value": resource,
                        "short": True
                    },
                    {
                        "title": "Severity",
                        "value": severity,
                        "short": True
                    },
                    {
                        "title": "Pull Request",
                        "value": f"<{pr_url}|View PR →>",
                        "short": False
                    }
                ],
                "footer": "CloudCompliance Auto-Remediation",
                "ts": int(datetime.now().timestamp())
            }
        ]
    }

    send_slack(payload)


def notify_compliance_score(score: int, passing: int, total: int, resources: int):
    webhook = get_webhook()
    if not webhook:
        return

    color = "#1D9E75" if score == 100 else "#f59e0b" if score >= 70 else "#ef4444"
    icon = ":white_check_mark:" if score == 100 else ":warning:" if score >= 70 else ":x:"

    payload = {
        "attachments": [
            {
                "color": color,
                "pretext": f"{icon} *CloudCompliance — SOC2 Compliance Report*",
                "fields": [
                    {
                        "title": "Compliance Score",
                        "value": f"*{score}%* ({passing}/{total} controls passing)",
                        "short": True
                    },
                    {
                        "title": "AWS Resources",
                        "value": str(resources),
                        "short": True
                    }
                ],
                "footer": "CloudCompliance",
                "ts": int(datetime.now().timestamp())
            }
        ]
    }

    send_slack(payload)


def notify_no_drift():
    webhook = get_webhook()
    if not webhook:
        return

    payload = {
        "attachments": [
            {
                "color": "#1D9E75",
                "pretext": ":white_check_mark: *CloudCompliance — No Drift Detected*",
                "text": "Infrastructure matches Terraform state. All resources are compliant.",
                "footer": "CloudCompliance Drift Detection",
                "ts": int(datetime.now().timestamp())
            }
        ]
    }

    send_slack(payload)
