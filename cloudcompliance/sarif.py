#!/usr/bin/env python3
"""
CloudCompliance — SARIF (Static Analysis Results Interchange Format) Generator
Generates OASIS SARIF v2.1.0 reports for direct integration into GitHub Security
Code Scanning Alerts (via github/codeql-action/upload-sarif).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional


def generate_sarif(
    results: Dict[str, Any],
    framework: str = "soc2",
    drift_findings: Optional[List[Dict[str, Any]]] = None,
    target_file: str = "terraform/main.tf",
) -> Dict[str, Any]:
    """
    Generate an OASIS SARIF v2.1.0 compliant dictionary from compliance evaluation
    and drift findings.
    """
    rules = []
    findings = []

    # Map framework controls to SARIF rules and findings
    for control_id, res in results.items():
        title = res.get("title", control_id)
        desc = res.get("description", title)
        status = res.get("status", "FAIL")

        rule_level = "error" if status == "FAIL" else "warning"

        rule = {
            "id": f"{framework.upper()}-{control_id}",
            "name": f"{control_id.replace('.', '_')}_{title.replace(' ', '_').replace('—', '_')}",
            "shortDescription": {"text": f"{control_id}: {title}"},
            "fullDescription": {"text": desc},
            "defaultConfiguration": {"level": rule_level},
            "helpUri": "https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance",
            "properties": {
                "framework": framework.upper(),
                "controlId": control_id,
                "precision": "high",
            },
        }
        rules.append(rule)

        # Only emit findings for non-PASS controls
        if status != "PASS":
            level = "error" if status == "FAIL" else "warning"
            missing = res.get("missing", [])
            missing_text = f"Missing required resources: {', '.join(missing)}" if missing else "Control criteria not fully satisfied."
            message_text = f"[{framework.upper()} {control_id}] {title} — {status}. {missing_text}"

            finding = {
                "ruleId": f"{framework.upper()}-{control_id}",
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            findings.append(finding)

    # Optional: include drift findings in SARIF
    if drift_findings:
        for finding_item in drift_findings:
            res_id = finding_item.get("resource_id", "unknown")
            drift_type = finding_item.get("drift_type", "DRIFT")
            sev = finding_item.get("severity", "HIGH").upper()
            level = "error" if sev in ("CRITICAL", "HIGH") else "warning"
            rule_id = f"DRIFT-{drift_type}"

            rule = {
                "id": rule_id,
                "name": f"Infrastructure_Drift_{drift_type}",
                "shortDescription": {"text": f"Infrastructure Drift: {drift_type}"},
                "fullDescription": {"text": "Discrepancy detected between live cloud infrastructure and declared Terraform state."},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": ["drift", "security", "cspm"]},
            }
            if not any(r["id"] == rule_id for r in rules):
                rules.append(rule)

            findings.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Drift detected on {res_id}: {finding_item.get('description', '')}. Remediation: {finding_item.get('remediation', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            })

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudCompliance",
                        "version": "2.2.0",
                        "informationUri": "https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
                "results": findings,
            }
        ],
    }
    return sarif_log


def save_sarif(
    sarif_data: Dict[str, Any],
    output_path: Path,
) -> Path:
    """Save SARIF dictionary to a formatted JSON file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(sarif_data, f, indent=2)
    return output_path
