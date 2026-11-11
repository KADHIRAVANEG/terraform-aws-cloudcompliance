#!/usr/bin/env python3
"""
CloudCompliance — Live Interactive Dashboard
FastAPI server serving real-time compliance posture, framework switching,
interactive on-demand drift detection, and full audit bundle (.zip) downloads.
"""

import io
import json
import os
import sqlite3
import zipfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, Request, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware


VALID_FRAMEWORKS = {"soc2", "hipaa", "pcidss"}


def sanitize_framework(framework: str) -> str:
    """Validate and sanitize compliance framework name against whitelist to prevent traversal."""
    fw = str(framework).strip().lower()
    if fw not in VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid framework: '{framework}'. Supported: {', '.join(sorted(VALID_FRAMEWORKS))}"
        )
    return fw


def get_allowed_origins() -> list:
    """Retrieve allowed CORS origins from environment or default to local development hosts."""
    env_origins = os.getenv("DASHBOARD_CORS_ORIGINS")
    if env_origins:
        return [o.strip() for o in env_origins.split(",") if o.strip()]
    return [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def verify_token(
    request: Optional[Request] = None,
    authorization: Optional[str] = None,
    x_api_key: Optional[str] = None,
):
    """
    Verify API access token when CLOUDCOMPLIANCE_API_KEY or DASHBOARD_API_KEY is configured.
    Supports Bearer header, X-API-Key header, and ?token= query parameter.
    """
    expected_token = os.getenv("CLOUDCOMPLIANCE_API_KEY") or os.getenv("DASHBOARD_API_KEY")
    if not expected_token:
        return True

    if request is None:
        # In direct unit tests or internal programmatic calls without request context
        return True

    # 1. Bearer header
    auth_val = authorization or request.headers.get("Authorization", "")
    if auth_val.startswith("Bearer "):
        token = auth_val.split("Bearer ", 1)[1].strip()
        if token == expected_token:
            return True

    # 2. X-API-Key header
    key_val = x_api_key or request.headers.get("X-API-Key", "")
    if key_val.strip() == expected_token:
        return True

    # 3. Query parameter ?token=
    query_token = request.query_params.get("token", "")
    if query_token.strip() == expected_token:
        return True

    raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API token")


def get_compliance_dir() -> Path:
    if os.environ.get("COMPLIANCE_DIR"):
        return Path(os.environ["COMPLIANCE_DIR"])
    cwd_dir = Path.cwd() / "compliance"
    if cwd_dir.exists():
        return cwd_dir
    pkg_dir = Path(__file__).parent.parent / "compliance"
    if pkg_dir.exists():
        return pkg_dir
    return cwd_dir


COMPLIANCE_DIR = get_compliance_dir()

app = FastAPI(title="CloudCompliance Interactive Dashboard", version="2.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True,
)


def load_json(path: Path) -> dict:
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def load_history(framework: str = "soc2") -> list:
    db_path = COMPLIANCE_DIR / "history.db"
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(compliance_history)")
        columns = [col[1] for col in cursor.fetchall()]
        if "framework" in columns:
            rows = conn.execute("""
                SELECT timestamp, score, controls_passing, controls_total, resources_count, framework
                FROM compliance_history
                WHERE LOWER(framework) = ?
                ORDER BY timestamp ASC
                LIMIT 30
            """, (framework.lower(),)).fetchall()
        else:
            rows = conn.execute("""
                SELECT timestamp, score, controls_passing, controls_total, resources_count
                FROM compliance_history
                ORDER BY timestamp ASC
                LIMIT 30
            """).fetchall()
        conn.close()
        return [
            {
                "timestamp": r[0],
                "score": r[1],
                "controls_passing": r[2],
                "controls_total": r[3],
                "resources_count": r[4],
                "framework": r[5] if len(r) > 5 else "soc2",
            }
            for r in rows
        ]
    except Exception:
        return []


@app.get("/api/status")
def get_status(framework: str = "soc2", request: Request = None):
    verify_token(request)
    fw = sanitize_framework(framework)
    report = load_json(COMPLIANCE_DIR / f"{fw}_compliance_report.json")
    if not report and fw == "soc2":
        report = load_json(COMPLIANCE_DIR / "compliance_report.json")

    # If report file doesn't exist yet, evaluate from available tfstate dynamically
    if not report:
        try:
            from cloudcompliance.report import get_default_tfstate_path, load_tfstate, extract_resources, load_controls, evaluate_controls
            tfstate_p = get_default_tfstate_path()
            if tfstate_p.exists():
                tfstate = load_tfstate(str(tfstate_p))
                resources = extract_resources(tfstate)
                controls = load_controls(fw)
                results = evaluate_controls(resources, controls, provider="aws")
                pass_count = sum(1 for r in results.values() if r.get("status") == "PASS")
                score = int((pass_count / len(results)) * 100) if results else 0
                report = {
                    "compliance_score": score,
                    "total_resources": len(resources),
                    "controls": results,
                    "generated_at": datetime.now().isoformat(),
                }
        except Exception:
            pass

    drift = load_json(COMPLIANCE_DIR / "drift_report.json")
    remediation = load_json(COMPLIANCE_DIR / "remediation_log.json")
    history = load_history(framework=fw)

    return JSONResponse({
        "generated_at": datetime.now().isoformat(),
        "framework": fw,
        "compliance": {
            "score": report.get("compliance_score", 0),
            "total_resources": report.get("total_resources", 0),
            "controls": report.get("controls", {}),
            "generated_at": report.get("generated_at", ""),
        },
        "drift": {
            "count": drift.get("drift_count", 0),
            "findings": drift.get("findings", []),
            "generated_at": drift.get("generated_at", ""),
        },
        "remediation": {
            "auto_fixed": remediation.get("auto_fixed", 0),
            "prs_opened": remediation.get("prs_opened", 0),
            "actions": remediation.get("actions", []),
            "pull_requests": remediation.get("pull_requests", []),
        },
        "history": history,
    })


@app.get("/api/framework/{framework_id}")
def get_framework_report(framework_id: str, request: Request = None):
    verify_token(request)
    fw = sanitize_framework(framework_id)
    return get_status(framework=fw, request=request)


@app.post("/api/actions/drift")
def trigger_drift_scan(request: Request = None):
    """Trigger real-time infrastructure drift evaluation on-demand."""
    verify_token(request)
    try:
        from cloudcompliance.report import get_default_tfstate_path
        from cloudcompliance.drift.detector import DriftDetector

        tfstate_path = get_default_tfstate_path()
        if not tfstate_path.exists():
            return JSONResponse({"status": "warning", "message": "terraform.tfstate not found for drift scan", "drift_count": 0, "findings": []})

        out_path = COMPLIANCE_DIR / "drift_report.json"
        detector = DriftDetector(
            tfstate_path=str(tfstate_path),
            demo=False,
            output_path=str(out_path),
        )
        count = detector.run()
        return JSONResponse({
            "status": "success",
            "drift_count": count,
            "findings": detector.drift_findings,
            "timestamp": datetime.now().isoformat(),
        })
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": str(e),
            "drift_count": 0,
            "findings": [],
        })


@app.get("/api/download/bundle")
def download_audit_bundle(request: Request = None):
    """Package and download all compliance evidence, reports, state, and hashes as an audit zip bundle."""
    verify_token(request)
    buf = io.BytesIO()
    timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    manifest = {
        "generated_at": datetime.now().isoformat(),
        "platform": "CloudCompliance v2.1.0",
        "scope": "AWS Cloud Security & Regulatory Compliance",
        "files": {},
    }

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Include compliance reports, markdown, pdf, and database
        if COMPLIANCE_DIR.exists():
            for p in COMPLIANCE_DIR.glob("*"):
                if p.is_file() and p.suffix in (".json", ".md", ".pdf", ".db"):
                    try:
                        content = p.read_bytes()
                        zf.writestr(f"evidence/{p.name}", content)
                        manifest["files"][f"evidence/{p.name}"] = {
                            "size_bytes": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                    except Exception:
                        pass

        # Include root terraform configuration files if present
        for tf_file in ["main.tf", "variables.tf", "outputs.tf", "versions.tf", "README.md"]:
            p = Path.cwd() / tf_file
            if p.exists() and p.is_file():
                try:
                    content = p.read_bytes()
                    zf.writestr(f"iac/{tf_file}", content)
                    manifest["files"][f"iac/{tf_file}"] = {
                        "size_bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                except Exception:
                    pass

        # Write manifest
        manifest_data = json.dumps(manifest, indent=2).encode("utf-8")
        zf.writestr("audit_manifest.json", manifest_data)

    buf.seek(0)
    bundle_filename = f"cloudcompliance-audit-bundle-{timestamp_str}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{bundle_filename}"'},
    )


@app.get("/metrics")
def get_metrics(request: Request = None):
    """Expose real-time compliance metrics in Prometheus exposition format."""
    verify_token(request)
    from cloudcompliance.metrics import generate_prometheus_metrics
    content = generate_prometheus_metrics(COMPLIANCE_DIR)
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudCompliance — Live Interactive Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@2.44.0/tabler-icons.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --green:#1D9E75;--green-bg:rgba(29,158,117,0.12);
  --yellow:#f59e0b;--yellow-bg:rgba(245,158,11,0.12);--yellow-text:#fbbf24;
  --red:#ef4444;--red-bg:rgba(239,68,68,0.12);--red-text:#f87171;
  --blue:#3b82f6;--blue-bg:rgba(59,130,246,0.12);--blue-text:#60a5fa;
  --purple:#8b5cf6;--purple-bg:rgba(139,92,246,0.12);
  --bg:#0b0d14;--s1:#141724;--s2:#1c2033;--border:#262a40;
  --text:#f1f5f9;--muted:#94a3b8;--mono:'Fira Code',monospace;--radius:8px;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
nav{display:flex;justify-content:space-between;align-items:center;padding:0 1.5rem;height:56px;border-bottom:1px solid var(--border);background:var(--s1);position:sticky;top:0;z-index:10}
.logo{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600}
.logo-mark{width:32px;height:32px;background:var(--green-bg);border:1px solid rgba(29,158,117,0.3);border-radius:8px;display:flex;align-items:center;justify-content:center}
.logo-mark i{font-size:18px;color:var(--green)}
.nav-controls{display:flex;align-items:center;gap:10px}
.fw-select{background:var(--s2);color:var(--text);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;font-size:12px;font-weight:500;outline:none;cursor:pointer}
.fw-select:hover{border-color:var(--green)}
.btn{padding:6px 14px;border-radius:var(--radius);font-size:12px;font-weight:500;border:1px solid var(--border);background:var(--s2);color:var(--text);cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .15s ease}
.btn:hover{background:#282e4a;border-color:#3a4163}
.btn-green{background:var(--green);border-color:var(--green);color:#fff}
.btn-green:hover{background:#16805f}
.btn-amber{background:rgba(245,158,11,0.15);color:var(--yellow-text);border-color:rgba(245,158,11,0.4)}
.btn-amber:hover{background:rgba(245,158,11,0.25)}
.btn-blue{background:rgba(59,130,246,0.15);color:var(--blue-text);border-color:rgba(59,130,246,0.4)}
.btn-blue:hover{background:rgba(59,130,246,0.25)}
.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.page{padding:1.75rem;max-width:1160px;margin:0 auto}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:1.5rem}
.kpi{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:1.15rem 1.25rem;transition:border-color .15s}
.kpi:hover{border-color:#3e4668}
.kpi-label{font-size:11px;color:var(--muted);margin-bottom:10px;display:flex;align-items:center;gap:6px;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.kpi-label i{font-size:15px}
.kpi-value{font-size:30px;font-weight:600;line-height:1;margin-bottom:4px}
.kpi-sub{font-size:12px;color:var(--muted)}
.kpi-badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:2px 8px;border-radius:20px;margin-top:8px}
.bg-green{background:var(--green-bg);color:var(--green)}
.bg-yellow{background:var(--yellow-bg);color:var(--yellow-text)}
.bg-red{background:var(--red-bg);color:var(--red-text)}
.bg-blue{background:var(--blue-bg);color:var(--blue-text)}
.score-wrap{display:flex;align-items:center;gap:14px}
.ring-wrap{position:relative;width:64px;height:64px;flex-shrink:0}
.ring-wrap svg{transform:rotate(-90deg)}
.ring-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600}
.grid-main{display:grid;grid-template-columns:1fr 340px;gap:14px;margin-bottom:1.5rem}
.card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:1.25rem}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;padding-bottom:10px;border-bottom:1px solid var(--border)}
.card-title{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;display:flex;align-items:center;gap:6px}
.card-meta{font-size:11px;color:var(--muted)}
.ctl{display:flex;align-items:center;gap:12px;padding:8px 10px;border-radius:6px;margin-bottom:3px;transition:background .15s}
.ctl:hover{background:var(--s2)}
.ctl-id{font-family:var(--mono);font-size:11px;color:var(--green);width:45px;flex-shrink:0}
.ctl-name{font-size:13px;flex:1}
.pill{font-size:10px;padding:2px 8px;border-radius:14px;font-weight:600;flex-shrink:0}
.pill-pass{background:var(--green-bg);color:var(--green)}
.pill-partial{background:var(--yellow-bg);color:var(--yellow-text)}
.pill-fail{background:var(--red-bg);color:var(--red-text)}
.finding{background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px}
.finding-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.finding-id{font-family:var(--mono);font-size:12px;font-weight:600}
.sev{font-size:10px;padding:2px 6px;border-radius:10px;font-weight:600}
.sev-high{background:var(--yellow-bg);color:var(--yellow-text)}
.sev-critical{background:var(--red-bg);color:var(--red-text)}
.finding-desc{font-size:12px;color:var(--muted);line-height:1.5}
.drift-empty{display:flex;flex-direction:column;align-items:center;padding:2rem;color:var(--muted);font-size:13px;gap:8px;text-align:center}
.drift-empty i{font-size:32px;color:var(--green)}
.chart-card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}
.chart-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem}
.chart-bars{display:flex;align-items:flex-end;gap:6px;height:90px;padding-bottom:22px;position:relative}
.chart-baseline{position:absolute;bottom:22px;left:0;right:0;border-top:1px dashed var(--border);pointer-events:none}
.bar-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px}
.bar{width:100%;border-radius:3px 3px 0 0;min-height:3px;transition:height .5s ease}
.bar-lbl{font-size:9px;color:var(--muted);position:absolute;bottom:-18px}
.bar-val{font-size:10px;color:var(--muted)}
.bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end;position:relative}
.actions-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.action-card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:1.15rem 1.25rem;cursor:pointer;transition:all .15s ease;text-decoration:none;color:inherit}
.action-card:hover{border-color:var(--green);transform:translateY(-2px);background:var(--s2)}
.action-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;margin-bottom:12px}
.action-icon i{font-size:20px}
.action-title{font-size:13px;font-weight:600;margin-bottom:4px}
.action-desc{font-size:12px;color:var(--muted);line-height:1.5}
.toast{position:fixed;bottom:20px;right:20px;background:#1e293b;border:1px solid var(--border);color:#fff;padding:10px 18px;border-radius:8px;font-size:13px;display:none;align-items:center;gap:8px;box-shadow:0 10px 25px rgba(0,0,0,0.5);z-index:99}
@media(max-width:768px){
  .kpi-row{grid-template-columns:1fr 1fr}
  .grid-main{grid-template-columns:1fr}
  .actions-row{grid-template-columns:1fr}
}
</style>
</head>
<body>
<nav>
  <div class="logo">
    <div class="logo-mark"><i class="ti ti-shield-check"></i></div>
    <span>CloudCompliance</span>
  </div>
  <div class="nav-controls">
    <select id="frameworkSelect" class="fw-select" onchange="onFrameworkChange(this.value)">
      <option value="soc2" selected>SOC 2 Type II</option>
      <option value="hipaa">HIPAA Security Rule</option>
      <option value="pcidss">PCI-DSS v4.0</option>
    </select>
    <button class="btn btn-amber" id="driftBtn" onclick="triggerDriftScan()"><i class="ti ti-radar"></i> Run Drift Scan</button>
    <button class="btn btn-blue" onclick="downloadBundle()"><i class="ti ti-download"></i> Audit Bundle (.zip)</button>
    <button class="btn btn-green" onclick="window.open('https://github.com/KADHIRAVANEG/terraform-aws-cloudcompliance','_blank')"><i class="ti ti-brand-github"></i></button>
  </div>
</nav>

<div class="page">
  <div class="kpi-row">
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-shield-check"></i> <span id="fwLabel">SOC2</span> Score</div>
      <div class="score-wrap">
        <div class="ring-wrap">
          <svg width="64" height="64" viewBox="0 0 64 64">
            <circle cx="32" cy="32" r="26" fill="none" stroke="var(--border)" stroke-width="5"/>
            <circle cx="32" cy="32" r="26" fill="none" id="ringStroke"
              stroke="#1D9E75" stroke-width="5" stroke-linecap="round"
              stroke-dasharray="163.36" stroke-dashoffset="163.36"/>
          </svg>
          <div class="ring-num" id="ringNum">–</div>
        </div>
        <div>
          <div class="kpi-value" id="scoreLabel" style="font-size:18px">–</div>
          <div class="kpi-sub" id="controlsSub">– controls</div>
          <span class="kpi-badge bg-green" id="scoreBadge"><i class="ti ti-check"></i> –</span>
        </div>
      </div>
    </div>
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-server"></i> AWS Resources</div>
      <div class="kpi-value" id="resourceVal">–</div>
      <div class="kpi-sub">analyzed across IaC</div>
      <span class="kpi-badge bg-green"><i class="ti ti-check"></i> Baseline Active</span>
    </div>
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-alert-triangle"></i> Drift Findings</div>
      <div class="kpi-value" id="driftVal">–</div>
      <div class="kpi-sub" id="driftSub">–</div>
      <span class="kpi-badge bg-green" id="driftBadge"><i class="ti ti-check"></i> Clean</span>
    </div>
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-git-pull-request"></i> Auto-Remediation</div>
      <div class="kpi-value" id="remediateVal">–</div>
      <div class="kpi-sub">PRs opened: <span id="prVal">–</span></div>
      <span class="kpi-badge bg-blue"><i class="ti ti-check"></i> Continuous</span>
    </div>
  </div>

  <div class="grid-main">
    <div class="card">
      <div class="card-header">
        <span class="card-title"><i class="ti ti-list-check"></i> <span id="controlsTitle">SOC2 Controls</span></span>
        <span class="card-meta" id="controlsMeta">–</span>
      </div>
      <div id="controlsList"><div style="color:var(--muted);font-size:13px;padding:.5rem">Loading controls...</div></div>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="card-title"><i class="ti ti-radar"></i> Infrastructure Drift</span>
        <span class="card-meta" id="driftMeta">–</span>
      </div>
      <div id="driftList"><div class="drift-empty"><i class="ti ti-circle-check"></i>Checking for drift...</div></div>
    </div>
  </div>

  <div class="chart-card">
    <div class="chart-header">
      <span class="card-title"><i class="ti ti-chart-line"></i> Compliance Score History</span>
      <span class="card-meta"><i class="ti ti-info-circle"></i> Point-in-time audit attestations</span>
    </div>
    <div class="chart-bars" id="chartBars">
      <div style="color:var(--muted);font-size:13px;margin:auto">No history yet — run 'cloudcompliance report'</div>
    </div>
  </div>

  <div class="actions-row">
    <div class="action-card" onclick="triggerDriftScan()">
      <div class="action-icon" style="background:var(--yellow-bg)"><i class="ti ti-radar" style="color:var(--yellow-text)"></i></div>
      <div class="action-title">Run Drift Scan Now</div>
      <div class="action-desc">Scan live AWS infrastructure against Terraform state to detect unauthorized changes.</div>
    </div>
    <div class="action-card" onclick="downloadBundle()">
      <div class="action-icon" style="background:var(--blue-bg)"><i class="ti ti-download" style="color:var(--blue-text)"></i></div>
      <div class="action-title">Download Audit Bundle (.zip)</div>
      <div class="action-desc">Download complete auditor package with JSON evidence, Markdown reports, and SHA-256 manifest.</div>
    </div>
    <div class="action-card" onclick="askAiPrompt()">
      <div class="action-icon" style="background:var(--purple-bg)"><i class="ti ti-sparkles" style="color:var(--purple)"></i></div>
      <div class="action-title">AI Compliance Assistant</div>
      <div class="action-desc">Query readiness: 'cloudcompliance ask "am I ready for SOC2 audit?"'</div>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
let currentFramework = 'soc2';
const urlParams = new URLSearchParams(window.location.search);
let authToken = urlParams.get('token') || localStorage.getItem('cc_dashboard_token') || '';
if (urlParams.get('token')) {
  localStorage.setItem('cc_dashboard_token', urlParams.get('token'));
}

function getAuthHeaders() {
  const headers = {};
  if (authToken) {
    headers['Authorization'] = 'Bearer ' + authToken;
    headers['X-API-Key'] = authToken;
  }
  return headers;
}

function showToast(msg, isError = false) {
  const t = document.getElementById('toast');
  t.innerHTML = (isError ? '⚠️ ' : '✅ ') + msg;
  t.style.display = 'flex';
  t.style.borderColor = isError ? 'var(--red)' : 'var(--green)';
  setTimeout(() => { t.style.display = 'none'; }, 4000);
}

function onFrameworkChange(fw) {
  currentFramework = fw;
  document.getElementById('fwLabel').textContent = fw.toUpperCase();
  document.getElementById('controlsTitle').textContent = fw.toUpperCase() + ' Controls';
  fetchStatus();
}

async function fetchStatus() {
  try {
    const url = '/api/status?framework=' + encodeURIComponent(currentFramework) + (authToken ? '&token=' + encodeURIComponent(authToken) : '');
    const res = await fetch(url, { headers: getAuthHeaders() });
    if (res.status === 401) {
      const entered = prompt('This CloudCompliance dashboard is protected with API Token Authentication.\nPlease enter your access token:');
      if (entered) {
        authToken = entered.trim();
        localStorage.setItem('cc_dashboard_token', authToken);
        return fetchStatus();
      }
      showToast('Authentication required (401 Unauthorized)', true);
      return;
    }
    const data = await res.json();
    render(data);
  } catch(e) {
    console.error(e);
  }
}

async function triggerDriftScan() {
  const btn = document.getElementById('driftBtn');
  const oldText = btn.innerHTML;
  btn.innerHTML = '<i class="ti ti-loader ti-spin"></i> Scanning...';
  btn.disabled = true;
  showToast('Initiating drift detection scan against AWS APIs...');

  try {
    const url = '/api/actions/drift' + (authToken ? '?token=' + encodeURIComponent(authToken) : '');
    const res = await fetch(url, { method: 'POST', headers: getAuthHeaders() });
    if (res.status === 401) {
      showToast('Action unauthorized: Invalid or missing token (401)', true);
      return;
    }
    const data = await res.json();
    if (data.status === 'success' || data.status === 'ok') {
      showToast('Drift scan complete: ' + data.drift_count + ' issues detected');
    } else {
      showToast('Drift scan completed with message: ' + (data.message || 'Complete'));
    }
    fetchStatus();
  } catch(e) {
    showToast('Failed to trigger drift scan: ' + e.message, true);
  } finally {
    btn.innerHTML = oldText;
    btn.disabled = false;
  }
}

function downloadBundle() {
  showToast('Preparing audit evidence bundle .zip...');
  const url = '/api/download/bundle' + (authToken ? '?token=' + encodeURIComponent(authToken) : '');
  window.location.href = url;
}

function askAiPrompt() {
  const q = prompt('Ask CloudCompliance AI Assistant:', 'What do I need to achieve 100% SOC2 compliance?');
  if (q) {
    alert('Run this command in your terminal:\n\ncloudcompliance ask "' + q + '"');
  }
}

function render(data) {
  const { compliance, drift, remediation, history } = data;
  const score = compliance.score || 0;
  const controls = compliance.controls || {};
  const passing = Object.values(controls).filter(c => c.status === 'PASS').length;
  const total = Object.keys(controls).length;

  const circ = 163.36;
  const offset = circ - (score / 100) * circ;
  const ring = document.getElementById('ringStroke');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = score === 100 ? '#1D9E75' : score >= 80 ? '#3b82f6' : score >= 50 ? '#f59e0b' : '#ef4444';

  document.getElementById('ringNum').textContent = score + '%';
  document.getElementById('scoreLabel').textContent = score === 100 ? 'Compliant' : score >= 80 ? 'Passing' : score >= 50 ? 'Partial' : 'Non-compliant';
  document.getElementById('scoreLabel').style.color = score === 100 ? 'var(--green)' : score >= 80 ? 'var(--blue-text)' : score >= 50 ? 'var(--yellow-text)' : 'var(--red-text)';
  document.getElementById('controlsSub').textContent = passing + '/' + total + ' passing';

  const sb = document.getElementById('scoreBadge');
  sb.className = 'kpi-badge ' + (score >= 80 ? 'bg-green' : 'bg-yellow');
  sb.innerHTML = score === 100 ? '<i class="ti ti-check"></i> Audit Ready' : score >= 80 ? '<i class="ti ti-check"></i> Guardrails Passing' : '<i class="ti ti-alert-triangle"></i> Remediation Required';

  document.getElementById('resourceVal').textContent = compliance.total_resources || '–';

  const dc = drift.count || 0;
  document.getElementById('driftVal').textContent = dc;
  document.getElementById('driftVal').style.color = dc === 0 ? 'var(--green)' : 'var(--yellow-text)';
  document.getElementById('driftSub').textContent = dc === 0 ? 'No drift detected' : dc + ' resource(s) changed';

  const db = document.getElementById('driftBadge');
  db.className = 'kpi-badge ' + (dc === 0 ? 'bg-green' : 'bg-yellow');
  db.innerHTML = dc === 0 ? '<i class="ti ti-check"></i> In Sync' : '<i class="ti ti-alert-triangle"></i> Out of Sync';

  document.getElementById('remediateVal').textContent = remediation.auto_fixed || 0;
  document.getElementById('prVal').textContent = remediation.prs_opened || 0;
  document.getElementById('controlsMeta').textContent = passing + '/' + total + ' passing';

  if (total > 0) {
    document.getElementById('controlsList').innerHTML = Object.entries(controls).map(([id, ctrl]) => {
      const pc = ctrl.status === 'PASS' ? 'pill-pass' : ctrl.status === 'PARTIAL' ? 'pill-partial' : 'pill-fail';
      const pl = ctrl.status === 'PASS' ? 'PASS' : ctrl.status === 'PARTIAL' ? 'PARTIAL' : 'FAIL';
      return '<div class="ctl"><span class="ctl-id">' + id + '</span><span class="ctl-name">' + ctrl.title + '</span><span class="pill ' + pc + '">' + pl + '</span></div>';
    }).join('');
  } else {
    document.getElementById('controlsList').innerHTML = '<div style="color:var(--muted);font-size:13px;padding:.5rem">No controls evaluated yet.</div>';
  }

  const findings = drift.findings || [];
  document.getElementById('driftMeta').textContent = findings.length + ' active';
  if (findings.length === 0) {
    document.getElementById('driftList').innerHTML = '<div class="drift-empty"><i class="ti ti-circle-check"></i>Infrastructure in sync with state</div>';
  } else {
    document.getElementById('driftList').innerHTML = findings.map(f => {
      const sc = f.severity === 'CRITICAL' ? 'sev-critical' : 'sev-high';
      return '<div class="finding"><div class="finding-top"><span class="finding-id">' + f.resource_id + '</span><span class="sev ' + sc + '">' + (f.severity || 'HIGH') + '</span></div><div class="finding-desc">' + f.description + '</div></div>';
    }).join('');
  }

  if (history && history.length > 0) {
    const maxH = 90;
    document.getElementById('chartBars').innerHTML = '<div class="chart-baseline"></div>' +
      history.map(h => {
        const pct = (h.score / 100) * maxH;
        const color = h.score === 100 ? '#1D9E75' : h.score >= 80 ? '#3b82f6' : h.score >= 50 ? '#f59e0b' : '#ef4444';
        const date = new Date(h.timestamp).toLocaleDateString('en', {month:'short',day:'numeric'});
        return '<div class="bar-col"><div class="bar-val">' + h.score + '%</div><div class="bar-wrap"><div class="bar" style="height:' + pct + 'px;background:' + color + '" title="' + date + ': ' + h.score + '%"></div></div><div class="bar-lbl">' + date + '</div></div>';
      }).join('');
  }
}

fetchStatus();
setInterval(fetchStatus, 30000);
</script>
</body>
</html>"""


def serve(host: str = "127.0.0.1", port: int = 8080, token: Optional[str] = None):
    import uvicorn
    if token:
        os.environ["CLOUDCOMPLIANCE_API_KEY"] = token
    has_token = bool(os.getenv("CLOUDCOMPLIANCE_API_KEY") or os.getenv("DASHBOARD_API_KEY"))

    print(f"\n  CloudCompliance Interactive Dashboard")
    print(f"  Running at http://{host}:{port}")
    print(f"  Framework switching: SOC2, HIPAA, PCI-DSS")
    print(f"  Actions enabled: On-demand drift scan, Audit bundle download (.zip)")
    if has_token:
        print(f"  Security: API Token Authentication [ENABLED]")
    else:
        print(f"  Security: Public mode (Tip: set --token <key> or CLOUDCOMPLIANCE_API_KEY)")
    print(f"  Press Ctrl+C to stop\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")
