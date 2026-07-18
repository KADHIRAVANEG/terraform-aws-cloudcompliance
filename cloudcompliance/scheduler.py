#!/usr/bin/env python3
"""
CloudCompliance — Scheduled Drift Detection
Runs drift detection automatically on a schedule
"""

import os
import time
import signal
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console

load_dotenv(Path(__file__).parent.parent / ".env")

console = Console()


def run_drift_check(tfstate_path: str, endpoint_url: str):
    console.print(f"\n[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — Running scheduled drift check...[/dim]")
    try:
        from cloudcompliance.drift.detector import DriftDetector
        detector = DriftDetector(
            tfstate_path=tfstate_path,
            endpoint_url=endpoint_url
        )
        drift_count = detector.run()
        if drift_count > 0:
            console.print(f"[yellow]⚠️  {drift_count} drift finding(s) — Slack alert sent[/yellow]")
        else:
            console.print(f"[green]✅ No drift detected[/green]")
        return drift_count
    except Exception as e:
        console.print(f"[red]Error during drift check: {e}[/red]")
        return -1


def schedule(
    interval_minutes: int = 60,
    endpoint_url: str = None,
    tfstate_path: str = None
):
    if tfstate_path is None:
        tfstate_path = str(Path(__file__).parent.parent / "terraform" / "terraform.tfstate")

    if endpoint_url is None:
        endpoint_url = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")

    console.print()
    console.print(f"[bold cyan]CloudCompliance — Scheduled Drift Detection[/bold cyan]")
    console.print(f"[dim]Interval: every {interval_minutes} minute(s)[/dim]")
    console.print(f"[dim]Endpoint: {endpoint_url}[/dim]")
    console.print(f"[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    def handle_exit(sig, frame):
        console.print("\n[dim]Scheduler stopped.[/dim]")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    run_count = 0
    while True:
        run_count += 1
        console.print(f"[dim]Run #{run_count}[/dim]")
        run_drift_check(tfstate_path, endpoint_url)
        console.print(f"[dim]Next check in {interval_minutes} minute(s)...[/dim]")
        time.sleep(interval_minutes * 60)
