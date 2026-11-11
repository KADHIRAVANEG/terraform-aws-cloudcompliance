#!/usr/bin/env python3
"""
CloudCompliance — Prometheus & OpenTelemetry Metrics Exporter
Exposes real-time compliance posture, controls health, drift counts,
and remediation counters in standard Prometheus text format (v0.0.4).
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from cloudcompliance.report import get_default_compliance_dir


def load_json_safe(path: Path) -> dict:
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def generate_prometheus_metrics(compliance_dir: Optional[Path] = None) -> str:
    """
    Generate Prometheus exposition format v0.0.4 metrics string from compliance state.
    """
    comp_dir = Path(compliance_dir) if compliance_dir else get_default_compliance_dir()
    frameworks = ["soc2", "hipaa", "pcidss"]

    lines = []
    lines.append("# CloudCompliance Prometheus Metrics Exporter")
    lines.append(f"# Generated: {datetime.now().isoformat()}\n")

    # Metrics collections
    scores = {}
    passing_controls = {}
    total_controls = {}
    resources_monitored = {}
    latest_timestamps = {}

    for fw in frameworks:
        report_file = comp_dir / f"{fw}_compliance_report.json"
        if not report_file.exists() and fw == "soc2":
            report_file = comp_dir / "compliance_report.json"

        data = load_json_safe(report_file)
        if data:
            scores[fw] = data.get("compliance_score", 0)
            resources_monitored[fw] = data.get("total_resources", 0)
            ctrls = data.get("controls", {})
            total_controls[fw] = len(ctrls)
            passing_controls[fw] = sum(1 for c in ctrls.values() if c.get("status") == "PASS")
            gen_at = data.get("generated_at")
            if gen_at:
                try:
                    dt = datetime.fromisoformat(gen_at)
                    latest_timestamps[fw] = int(dt.timestamp())
                except Exception:
                    latest_timestamps[fw] = int(time.time())

    # Fallback default if no report files exist yet
    if not scores:
        scores["soc2"] = 0
        total_controls["soc2"] = 0
        passing_controls["soc2"] = 0
        resources_monitored["soc2"] = 0
        latest_timestamps["soc2"] = int(time.time())

    # 1. Compliance Score
    lines.append("# HELP cloudcompliance_score Compliance score percentage (0-100)")
    lines.append("# TYPE cloudcompliance_score gauge")
    for fw, score in scores.items():
        lines.append(f'cloudcompliance_score{{framework="{fw}"}} {score}')
    lines.append("")

    # 2. Controls Passing
    lines.append("# HELP cloudcompliance_controls_passing Number of passing compliance controls")
    lines.append("# TYPE cloudcompliance_controls_passing gauge")
    for fw, cnt in passing_controls.items():
        lines.append(f'cloudcompliance_controls_passing{{framework="{fw}"}} {cnt}')
    lines.append("")

    # 3. Controls Total
    lines.append("# HELP cloudcompliance_controls_total Total number of evaluated compliance controls")
    lines.append("# TYPE cloudcompliance_controls_total gauge")
    for fw, cnt in total_controls.items():
        lines.append(f'cloudcompliance_controls_total{{framework="{fw}"}} {cnt}')
    lines.append("")

    # 4. Resources Monitored
    lines.append("# HELP cloudcompliance_resources_monitored Total number of active cloud resources audited")
    lines.append("# TYPE cloudcompliance_resources_monitored gauge")
    for fw, cnt in resources_monitored.items():
        lines.append(f'cloudcompliance_resources_monitored{{framework="{fw}"}} {cnt}')
    lines.append("")

    # 5. Drift Findings
    drift_data = load_json_safe(comp_dir / "drift_report.json")
    drift_count = drift_data.get("drift_count", 0)
    lines.append("# HELP cloudcompliance_drift_count Total number of detected infrastructure drift findings")
    lines.append("# TYPE cloudcompliance_drift_count gauge")
    lines.append(f"cloudcompliance_drift_count {drift_count}")
    lines.append("")

    # 6. Auto-Remediation Stats
    remed_data = load_json_safe(comp_dir / "remediation_log.json")
    auto_fixed = remed_data.get("auto_fixed", 0)
    prs_opened = remed_data.get("prs_opened", 0)
    lines.append("# HELP cloudcompliance_remediation_auto_fixed_total Total number of drift issues automatically remediated")
    lines.append("# TYPE cloudcompliance_remediation_auto_fixed_total counter")
    lines.append(f"cloudcompliance_remediation_auto_fixed_total {auto_fixed}")
    lines.append("")

    lines.append("# HELP cloudcompliance_remediation_prs_opened_total Total number of remediation pull requests opened")
    lines.append("# TYPE cloudcompliance_remediation_prs_opened_total counter")
    lines.append(f"cloudcompliance_remediation_prs_opened_total {prs_opened}")
    lines.append("")

    # 7. Last Scan Timestamps
    lines.append("# HELP cloudcompliance_last_scan_timestamp Unix timestamp of latest compliance evaluation")
    lines.append("# TYPE cloudcompliance_last_scan_timestamp gauge")
    for fw, ts in latest_timestamps.items():
        lines.append(f'cloudcompliance_last_scan_timestamp{{framework="{fw}"}} {ts}')
    lines.append("")

    return "\n".join(lines) + "\n"
