#!/usr/bin/env python3
"""
CloudCompliance — AI Compliance Assistant
Powered by NVIDIA NIM (meta/llama-3.1-8b-instruct)
Answers questions about your actual compliance state
"""

import json
import os
import sys
from pathlib import Path

import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

console = Console()

NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = "meta/llama-3.1-8b-instruct"


def load_context() -> dict:
    """Load compliance report, drift report and tfstate as context."""
    base = Path(__file__).parent.parent
    context = {}

    report_path = base / "compliance" / "compliance_report.json"
    if report_path.exists():
        with open(report_path) as f:
            context["compliance_report"] = json.load(f)

    drift_path = base / "compliance" / "drift_report.json"
    if drift_path.exists():
        with open(drift_path) as f:
            context["drift_report"] = json.load(f)

    history_path = base / "compliance" / "history_export.json"
    if history_path.exists():
        with open(history_path) as f:
            context["history"] = json.load(f)

    tfstate_path = base / "terraform" / "terraform.tfstate"
    if tfstate_path.exists():
        with open(tfstate_path) as f:
            state = json.load(f)
            context["resource_count"] = len(state.get("resources", []))
            context["resource_types"] = list(set(
                r.get("type") for r in state.get("resources", [])
            ))

    return context


def build_system_prompt(context: dict) -> str:
    return f"""You are CloudCompliance AI — an expert SOC2 compliance assistant.
You have access to the user's actual AWS infrastructure compliance data.

COMPLIANCE REPORT:
{json.dumps(context.get("compliance_report", {}), indent=2)}

DRIFT REPORT:
{json.dumps(context.get("drift_report", {}), indent=2)}

INFRASTRUCTURE SUMMARY:
- Total resources: {context.get("resource_count", "unknown")}
- Resource types present: {", ".join(context.get("resource_types", []))}

INSTRUCTIONS:
- Answer questions about the user's actual compliance state
- Be specific — reference actual controls, scores, and resources from their data
- Give actionable recommendations
- If drift was detected, explain the risk and how to fix it
- Keep answers concise and practical
- Format with markdown for clarity
- Never make up data — only reference what's in the reports above
"""


def ask(question: str, api_key: str):
    context = load_context()

    if not context:
        console.print("[red]Error: No compliance data found. Run 'cloudcompliance report' first.[/red]")
        sys.exit(1)

    system_prompt = build_system_prompt(context)

    console.print()
    console.print(Panel.fit(
        f"[bold cyan]CloudCompliance AI[/bold cyan]\n[dim]Powered by NVIDIA NIM — {MODEL}[/dim]",
        border_style="cyan"
    ))
    console.print()
    console.print(f"[dim]Question:[/dim] {question}")
    console.print()

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ],
        "max_tokens": 1024,
        "temperature": 0.3,
        "stream": False
    }

    try:
        response = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        answer = data["choices"][0]["message"]["content"]

        console.print(Panel(
            Markdown(answer),
            title="[bold green]AI Response[/bold green]",
            border_style="green"
        ))

    except requests.exceptions.Timeout:
        console.print("[red]Error: Request timed out. Check your network.[/red]")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        console.print(f"[red]Error: API request failed — {e}[/red]")
        sys.exit(1)
    except KeyError:
        console.print("[red]Error: Unexpected API response format.[/red]")
        sys.exit(1)


def main(question: str, api_key: str = None):
    if api_key is None:
        api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        console.print("[red]Error: NVIDIA_API_KEY not set.[/red]")
        console.print("[dim]Export it: export NVIDIA_API_KEY='your-key'[/dim]")
        sys.exit(1)
    ask(question, api_key)
