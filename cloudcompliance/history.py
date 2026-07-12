#!/usr/bin/env python3
"""
CloudCompliance — Compliance Score History
Stores compliance scores over time for SOC2 Type II evidence
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

DB_PATH = Path(__file__).parent.parent / "compliance" / "history.db"


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            score INTEGER NOT NULL,
            controls_passing INTEGER NOT NULL,
            controls_total INTEGER NOT NULL,
            resources_count INTEGER NOT NULL,
            report_json TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def save_score(report_path: Path):
    """Save compliance score from report JSON to history database."""
    if not report_path.exists():
        console.print(f"[red]Error: report not found at {report_path}[/red]")
        return

    with open(report_path) as f:
        report = json.load(f)

    score = report.get("compliance_score", 0)
    total_resources = report.get("total_resources", 0)
    controls = report.get("controls", {})
    controls_passing = sum(
        1 for c in controls.values() if c.get("status") == "PASS"
    )
    controls_total = len(controls)

    conn = get_db()
    conn.execute("""
        INSERT INTO compliance_history
        (timestamp, score, controls_passing, controls_total, resources_count, report_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        score,
        controls_passing,
        controls_total,
        total_resources,
        json.dumps(report)
    ))
    conn.commit()
    conn.close()

    console.print(f"[dim]Score saved to history: {score}% ({controls_passing}/{controls_total} controls)[/dim]")


def show_history(limit: int = 10):
    """Display compliance score history table."""
    conn = get_db()
    rows = conn.execute("""
        SELECT timestamp, score, controls_passing, controls_total, resources_count
        FROM compliance_history
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    if not rows:
        console.print(Panel.fit(
            "[yellow]No history yet — run 'cloudcompliance report' first[/yellow]",
            border_style="yellow"
        ))
        return

    console.print()
    console.print(Panel.fit(
        "[bold cyan]CloudCompliance — Score History[/bold cyan]\n"
        f"[dim]SOC2 Type II evidence timeline — last {len(rows)} entries[/dim]",
        border_style="cyan"
    ))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Date", style="cyan", width=20)
    table.add_column("Score", width=8)
    table.add_column("Controls", width=12)
    table.add_column("Resources", width=10)
    table.add_column("Trend", width=10)

    prev_score = None
    for i, row in enumerate(reversed(rows)):
        timestamp, score, passing, total, resources = row
        dt = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M")

        score_color = "green" if score == 100 else "yellow" if score >= 70 else "red"
        score_str = f"[{score_color}]{score}%[/{score_color}]"

        controls_str = f"{passing}/{total}"

        if prev_score is None:
            trend = "[dim]—[/dim]"
        elif score > prev_score:
            trend = f"[green]↑ +{score - prev_score}%[/green]"
        elif score < prev_score:
            trend = f"[red]↓ -{prev_score - score}%[/red]"
        else:
            trend = "[dim]→ 0%[/dim]"

        table.add_row(dt, score_str, controls_str, str(resources), trend)
        prev_score = score

    console.print(table)
    console.print()

    scores = [r[1] for r in rows]
    avg = sum(scores) / len(scores)
    best = max(scores)
    latest = rows[0][1]

    console.print(Panel.fit(
        f"[bold]Latest:[/bold] {latest}%  "
        f"[bold]Best:[/bold] {best}%  "
        f"[bold]Average:[/bold] {avg:.1f}%  "
        f"[bold]Entries:[/bold] {len(rows)}",
        border_style="cyan"
    ))


def export_history(output_path: Path = None):
    """Export history as JSON for auditors."""
    conn = get_db()
    rows = conn.execute("""
        SELECT timestamp, score, controls_passing, controls_total, resources_count
        FROM compliance_history
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()

    data = {
        "exported_at": datetime.now().isoformat(),
        "entry_count": len(rows),
        "entries": [
            {
                "timestamp": r[0],
                "score": r[1],
                "controls_passing": r[2],
                "controls_total": r[3],
                "resources_count": r[4]
            }
            for r in rows
        ]
    }

    if output_path is None:
        output_path = Path(__file__).parent.parent / "compliance" / "history_export.json"

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[dim]History exported → {output_path}[/dim]")
    return data
