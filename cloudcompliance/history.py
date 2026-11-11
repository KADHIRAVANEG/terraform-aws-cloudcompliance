#!/usr/bin/env python3
"""
CloudCompliance — Compliance Score History
Stores compliance scores over time for SOC2 Type II evidence
"""

import json
import os
import sqlite3
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


def get_db_path() -> Path:
    """Resolve database path dynamically."""
    db_env = os.environ.get("CLOUDCOMPLIANCE_DB_PATH")
    if db_env:
        return Path(db_env)
    return get_default_compliance_dir() / "history.db"


def get_db(db_path: Path = None) -> sqlite3.Connection:
    target_path = Path(db_path) if db_path else get_db_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            framework TEXT NOT NULL DEFAULT 'soc2',
            score INTEGER NOT NULL,
            controls_passing INTEGER NOT NULL,
            controls_total INTEGER NOT NULL,
            resources_count INTEGER NOT NULL,
            report_json TEXT NOT NULL
        )
    """)
    # Automatic migration: add framework column if missing in older database
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(compliance_history)")
    columns = [col[1] for col in cursor.fetchall()]
    if "framework" not in columns:
        conn.execute("ALTER TABLE compliance_history ADD COLUMN framework TEXT NOT NULL DEFAULT 'soc2'")
    conn.commit()
    return conn


def save_score(report_path: Path, db_path: Path = None, framework: str = "soc2"):
    """Save compliance score from report JSON to history database with framework isolation."""
    report_file = Path(report_path)
    if not report_file.exists():
        console.print(f"[red]Error: report not found at {report_file}[/red]")
        return

    with open(report_file) as f:
        report = json.load(f)

    fw = (report.get("framework") or framework or "soc2").lower()
    score = report.get("compliance_score", 0)
    total_resources = report.get("total_resources", 0)
    controls = report.get("controls", {})
    controls_passing = sum(
        1 for c in controls.values() if c.get("status") == "PASS"
    )
    controls_total = len(controls)

    conn = get_db(db_path=db_path)
    conn.execute("""
        INSERT INTO compliance_history
        (timestamp, framework, score, controls_passing, controls_total, resources_count, report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        fw,
        score,
        controls_passing,
        controls_total,
        total_resources,
        json.dumps(report)
    ))
    conn.commit()
    conn.close()

    console.print(f"[dim]Score saved to history ({fw.upper()}): {score}% ({controls_passing}/{controls_total} controls)[/dim]")


def show_history(limit: int = 10, db_path: Path = None, framework: str = None):
    """Display compliance score history table with optional framework filtering."""
    conn = get_db(db_path=db_path)
    if framework:
        fw = framework.lower()
        rows = conn.execute("""
            SELECT timestamp, score, controls_passing, controls_total, resources_count, framework
            FROM compliance_history
            WHERE LOWER(framework) = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (fw, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT timestamp, score, controls_passing, controls_total, resources_count, framework
            FROM compliance_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    conn.close()

    if not rows:
        fw_msg = f" for '{framework.upper()}'" if framework else ""
        console.print(Panel.fit(
            f"[yellow]No history yet{fw_msg} — run 'cloudcompliance report' first[/yellow]",
            border_style="yellow"
        ))
        return

    fw_title = f"{framework.upper()} " if framework else "Multi-Framework "
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]CloudCompliance — {fw_title}Score History[/bold cyan]\n"
        f"[dim]Audit evidence timeline — last {len(rows)} entries[/dim]",
        border_style="cyan"
    ))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Date", style="cyan", width=18)
    table.add_column("Framework", style="bold blue", width=10)
    table.add_column("Score", width=8)
    table.add_column("Controls", width=12)
    table.add_column("Resources", width=10)
    table.add_column("Trend", width=10)

    prev_score = None
    for i, row in enumerate(reversed(rows)):
        timestamp, score, passing, total, resources, row_fw = row
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

        table.add_row(dt, row_fw.upper(), score_str, controls_str, str(resources), trend)
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


def export_history(output_path: Path = None, db_path: Path = None, framework: str = None):
    """Export history as JSON for auditors with framework isolation."""
    conn = get_db(db_path=db_path)
    if framework:
        fw = framework.lower()
        rows = conn.execute("""
            SELECT timestamp, score, controls_passing, controls_total, resources_count, framework
            FROM compliance_history
            WHERE LOWER(framework) = ?
            ORDER BY timestamp ASC
        """, (fw,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT timestamp, score, controls_passing, controls_total, resources_count, framework
            FROM compliance_history
            ORDER BY timestamp ASC
        """).fetchall()
    conn.close()

    data = {
        "exported_at": datetime.now().isoformat(),
        "framework_scope": framework.upper() if framework else "ALL",
        "entry_count": len(rows),
        "entries": [
            {
                "timestamp": r[0],
                "framework": r[5] if len(r) > 5 else "soc2",
                "score": r[1],
                "controls_passing": r[2],
                "controls_total": r[3],
                "resources_count": r[4]
            }
            for r in rows
        ]
    }

    if output_path is None:
        fname = f"{framework.lower()}_history_export.json" if framework else "history_export.json"
        output_path = get_default_compliance_dir() / fname
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[dim]History exported → {output_path}[/dim]")
    return data
