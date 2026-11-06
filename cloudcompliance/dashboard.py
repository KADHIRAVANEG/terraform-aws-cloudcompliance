#!/usr/bin/env python3
"""
CloudCompliance — Live Dashboard
FastAPI server serving real-time compliance data
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import os

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
BASE = COMPLIANCE_DIR.parent

app = FastAPI(title="CloudCompliance Dashboard", version="1.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_json(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def load_history() -> list:
    db_path = COMPLIANCE_DIR / "history.db"
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
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
            "resources_count": r[4]
        }
        for r in rows
    ]


@app.get("/api/status")
def get_status():
    report = load_json(COMPLIANCE_DIR / "compliance_report.json")
    if not report:
        report = load_json(COMPLIANCE_DIR / "soc2_compliance_report.json")
    drift = load_json(COMPLIANCE_DIR / "drift_report.json")
    remediation = load_json(COMPLIANCE_DIR / "remediation_log.json")
    history = load_history()

    return JSONResponse({
        "generated_at": datetime.now().isoformat(),
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


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudCompliance Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@2.44.0/tabler-icons.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --green:#1D9E75;--green-bg:rgba(29,158,117,0.1);
  --yellow:#f59e0b;--yellow-bg:rgba(245,158,11,0.1);--yellow-text:#d97706;
  --red:#ef4444;--red-bg:rgba(239,68,68,0.1);--red-text:#dc2626;
  --blue:#3b82f6;--blue-bg:rgba(59,130,246,0.1);--blue-text:#2563eb;
  --purple:#8b5cf6;--purple-bg:rgba(139,92,246,0.1);
  --bg:#0f1117;--s1:#1a1d27;--s2:#222536;--border:#2a2d3e;
  --text:#e2e8f0;--muted:#8892a4;--mono:'Fira Code',monospace;--radius:8px;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
nav{display:flex;justify-content:space-between;align-items:center;padding:0 1.5rem;height:52px;border-bottom:0.5px solid var(--border);background:var(--s1);position:sticky;top:0;z-index:10}
.logo{display:flex;align-items:center;gap:8px;font-size:15px;font-weight:500}
.logo-mark{width:28px;height:28px;background:var(--green-bg);border-radius:7px;display:flex;align-items:center;justify-content:center}
.logo-mark i{font-size:16px;color:var(--green)}
.nav-right{display:flex;align-items:center;gap:10px}
.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.btn{padding:5px 12px;border-radius:var(--radius);font-size:12px;border:0.5px solid var(--border);background:transparent;color:var(--text);cursor:pointer;display:flex;align-items:center;gap:6px;transition:background .15s}
.btn:hover{background:var(--s2)}
.btn-green{background:var(--green);border-color:var(--green);color:#fff}
.btn-green:hover{background:#18876a}
.page{padding:1.5rem;max-width:1100px;margin:0 auto}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.5rem}
.kpi{background:var(--s1);border:0.5px solid var(--border);border-radius:12px;padding:1rem 1.25rem}
.kpi-label{font-size:11px;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:5px;text-transform:uppercase;letter-spacing:.05em}
.kpi-label i{font-size:14px}
.kpi-value{font-size:30px;font-weight:500;line-height:1;margin-bottom:4px}
.kpi-sub{font-size:12px;color:var(--muted)}
.kpi-badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:2px 8px;border-radius:20px;margin-top:8px}
.bg-green{background:var(--green-bg);color:var(--green)}
.bg-yellow{background:var(--yellow-bg);color:var(--yellow-text)}
.bg-red{background:var(--red-bg);color:var(--red-text)}
.bg-blue{background:var(--blue-bg);color:var(--blue-text)}
.score-wrap{display:flex;align-items:center;gap:12px}
.ring-wrap{position:relative;width:60px;height:60px;flex-shrink:0}
.ring-wrap svg{transform:rotate(-90deg)}
.ring-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:500}
.grid-main{display:grid;grid-template-columns:1fr 320px;gap:12px;margin-bottom:1.5rem}
.card{background:var(--s1);border:0.5px solid var(--border);border-radius:12px;padding:1.25rem}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}
.card-title{font-size:13px;font-weight:500}
.card-meta{font-size:11px;color:var(--muted)}
.ctl{display:flex;align-items:center;gap:10px;padding:7px 8px;border-radius:6px;margin-bottom:2px}
.ctl:hover{background:var(--s2)}
.ctl-id{font-family:var(--mono);font-size:11px;color:var(--green);width:40px;flex-shrink:0}
.ctl-name{font-size:13px;flex:1}
.pill{font-size:10px;padding:2px 8px;border-radius:20px;flex-shrink:0}
.pill-pass{background:var(--green-bg);color:var(--green)}
.pill-partial{background:var(--yellow-bg);color:var(--yellow-text)}
.pill-fail{background:var(--red-bg);color:var(--red-text)}
.finding{background:var(--s2);border:0.5px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px}
.finding-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.finding-id{font-family:var(--mono);font-size:12px;font-weight:500}
.sev{font-size:10px;padding:2px 6px;border-radius:10px}
.sev-high{background:var(--yellow-bg);color:var(--yellow-text)}
.sev-critical{background:var(--red-bg);color:var(--red-text)}
.finding-desc{font-size:12px;color:var(--muted);line-height:1.5}
.drift-empty{display:flex;flex-direction:column;align-items:center;padding:1.5rem;color:var(--muted);font-size:13px;gap:8px;text-align:center}
.drift-empty i{font-size:28px;color:var(--green)}
.pr-notice{margin-top:8px;padding:8px 12px;background:var(--green-bg);border-radius:6px;font-size:12px;color:var(--green);display:flex;align-items:center;gap:8px}
.chart-card{background:var(--s1);border:0.5px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}
.chart-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem}
.chart-bars{display:flex;align-items:flex-end;gap:6px;height:90px;padding-bottom:22px;position:relative}
.chart-baseline{position:absolute;bottom:22px;left:0;right:0;border-top:0.5px dashed var(--border);pointer-events:none}
.bar-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px}
.bar{width:100%;border-radius:3px 3px 0 0;min-height:3px;transition:height .5s ease}
.bar-lbl{font-size:9px;color:var(--muted);position:absolute;bottom:-18px}
.bar-val{font-size:10px;color:var(--muted)}
.bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end;position:relative}
.actions-row{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.action{background:var(--s1);border:0.5px solid var(--border);border-radius:12px;padding:1rem 1.25rem;cursor:pointer;transition:border-color .15s}
.action:hover{border-color:#4a5568}
.action-icon{width:32px;height:32px;border-radius:7px;display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.action-icon i{font-size:17px}
.action-title{font-size:13px;font-weight:500;margin-bottom:3px}
.action-desc{font-size:12px;color:var(--muted);line-height:1.5}
@media(max-width:700px){
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
    CloudCompliance
  </div>
  <div class="nav-right">
    <div class="live"><div class="dot"></div><span id="lastUpdated">Loading...</span></div>
    <button class="btn" onclick="fetchStatus()"><i class="ti ti-refresh"></i> Refresh</button>
    <button class="btn btn-green" onclick="window.open('https://github.com/KADHIRAVANEG/cloudcompliance','_blank')"><i class="ti ti-brand-github"></i> GitHub</button>
  </div>
</nav>
<div class="page">
  <div class="kpi-row">
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-shield-check"></i> Compliance score</div>
      <div class="score-wrap">
        <div class="ring-wrap">
          <svg width="60" height="60" viewBox="0 0 60 60">
            <circle cx="30" cy="30" r="24" fill="none" stroke="var(--border)" stroke-width="5"/>
            <circle cx="30" cy="30" r="24" fill="none" id="ringStroke"
              stroke="#1D9E75" stroke-width="5" stroke-linecap="round"
              stroke-dasharray="150.8" stroke-dashoffset="150.8"/>
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
      <div class="kpi-label"><i class="ti ti-server"></i> AWS resources</div>
      <div class="kpi-value" id="resourceVal">–</div>
      <div class="kpi-sub">provisioned</div>
      <span class="kpi-badge bg-green"><i class="ti ti-check"></i> Healthy</span>
    </div>
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-alert-triangle"></i> Drift findings</div>
      <div class="kpi-value" id="driftVal">–</div>
      <div class="kpi-sub" id="driftSub">–</div>
      <span class="kpi-badge bg-green" id="driftBadge"><i class="ti ti-check"></i> –</span>
    </div>
    <div class="kpi">
      <div class="kpi-label"><i class="ti ti-git-pull-request"></i> Auto-remediation</div>
      <div class="kpi-value" id="remediateVal">–</div>
      <div class="kpi-sub">PRs opened: <span id="prVal">–</span></div>
      <span class="kpi-badge bg-blue"><i class="ti ti-check"></i> Automated</span>
    </div>
  </div>
  <div class="grid-main">
    <div class="card">
      <div class="card-header">
        <span class="card-title">SOC2 controls</span>
        <span class="card-meta" id="controlsMeta">–</span>
      </div>
      <div id="controlsList"><div style="color:var(--muted);font-size:13px;padding:.5rem">Loading...</div></div>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="card-title">Drift findings</span>
        <span class="card-meta" id="driftMeta">–</span>
      </div>
      <div id="driftList"><div class="drift-empty"><i class="ti ti-circle-check"></i>Checking...</div></div>
    </div>
  </div>
  <div class="chart-card">
    <div class="chart-header">
      <span class="card-title">Compliance score history</span>
      <span class="card-meta"><i class="ti ti-info-circle"></i> SOC2 Type II evidence timeline</span>
    </div>
    <div class="chart-bars" id="chartBars">
      <div style="color:var(--muted);font-size:13px;margin:auto">No history yet — run cloudcompliance report</div>
    </div>
  </div>
  <div class="actions-row">
    <div class="action">
      <div class="action-icon" style="background:var(--purple-bg)"><i class="ti ti-sparkles" style="color:var(--purple)"></i></div>
      <div class="action-title">Ask AI assistant</div>
      <div class="action-desc">cloudcompliance ask "am I ready for SOC2 audit?"</div>
    </div>
    <div class="action">
      <div class="action-icon" style="background:var(--yellow-bg)"><i class="ti ti-radar" style="color:var(--yellow-text)"></i></div>
      <div class="action-title">Run drift scan</div>
      <div class="action-desc">cloudcompliance drift</div>
    </div>
    <div class="action">
      <div class="action-icon" style="background:var(--blue-bg)"><i class="ti ti-download" style="color:var(--blue-text)"></i></div>
      <div class="action-title">Export audit evidence</div>
      <div class="action-desc">cloudcompliance history --export</div>
    </div>
  </div>
</div>
<script>
async function fetchStatus() {
  document.getElementById('lastUpdated').textContent = 'Refreshing...';
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    render(data);
    document.getElementById('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('lastUpdated').textContent = 'Connection error';
  }
}
function render(data) {
  const { compliance, drift, remediation, history } = data;
  const score = compliance.score || 0;
  const controls = compliance.controls || {};
  const passing = Object.values(controls).filter(c => c.status === 'PASS').length;
  const total = Object.keys(controls).length;
  const circ = 150.8;
  const offset = circ - (score / 100) * circ;
  const ring = document.getElementById('ringStroke');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = score === 100 ? '#1D9E75' : score >= 70 ? '#f59e0b' : '#ef4444';
  document.getElementById('ringNum').textContent = score + '%';
  document.getElementById('scoreLabel').textContent = score === 100 ? 'Compliant' : score >= 70 ? 'Partial' : 'Non-compliant';
  document.getElementById('scoreLabel').style.color = score === 100 ? 'var(--green)' : score >= 70 ? 'var(--yellow-text)' : 'var(--red-text)';
  document.getElementById('controlsSub').textContent = passing + '/' + total + ' controls';
  const sb = document.getElementById('scoreBadge');
  sb.className = 'kpi-badge ' + (score === 100 ? 'bg-green' : 'bg-yellow');
  sb.innerHTML = score === 100 ? '<i class="ti ti-check"></i> All clear' : '<i class="ti ti-alert-triangle"></i> Needs work';
  document.getElementById('resourceVal').textContent = compliance.total_resources || '–';
  const dc = drift.count || 0;
  document.getElementById('driftVal').textContent = dc;
  document.getElementById('driftVal').style.color = dc === 0 ? 'var(--green)' : 'var(--yellow-text)';
  document.getElementById('driftSub').textContent = dc === 0 ? 'No drift detected' : dc + ' resource(s) changed';
  const db = document.getElementById('driftBadge');
  db.className = 'kpi-badge ' + (dc === 0 ? 'bg-green' : 'bg-yellow');
  db.innerHTML = dc === 0 ? '<i class="ti ti-check"></i> Clean' : '<i class="ti ti-clock"></i> Pending fix';
  document.getElementById('remediateVal').textContent = remediation.auto_fixed || 0;
  document.getElementById('prVal').textContent = remediation.prs_opened || 0;
  document.getElementById('controlsMeta').textContent = passing + '/' + total + ' passing';
  if (total > 0) {
    document.getElementById('controlsList').innerHTML = Object.entries(controls).map(([id, ctrl]) => {
      const pc = ctrl.status === 'PASS' ? 'pill-pass' : ctrl.status === 'PARTIAL' ? 'pill-partial' : 'pill-fail';
      const pl = ctrl.status === 'PASS' ? 'PASS' : ctrl.status === 'PARTIAL' ? 'PARTIAL' : 'FAIL';
      return '<div class="ctl"><span class="ctl-id">' + id + '</span><span class="ctl-name">' + ctrl.title + '</span><span class="pill ' + pc + '">' + pl + '</span></div>';
    }).join('');
  }
  const findings = drift.findings || [];
  document.getElementById('driftMeta').textContent = findings.length + ' active';
  if (findings.length === 0) {
    document.getElementById('driftList').innerHTML = '<div class="drift-empty"><i class="ti ti-circle-check"></i>No drift detected</div>';
  } else {
    const prs = remediation.pull_requests || [];
    document.getElementById('driftList').innerHTML = findings.map(f => {
      const sc = f.severity === 'CRITICAL' ? 'sev-critical' : 'sev-high';
      const pr = prs.find(p => p.resource === f.resource_id);
      return '<div class="finding"><div class="finding-top"><span class="finding-id">' + f.resource_id + '</span><span class="sev ' + sc + '">' + f.severity + '</span></div><div class="finding-desc">' + f.description + '</div>' + (pr ? '<div class="pr-notice"><i class="ti ti-git-pull-request"></i><a href="' + pr.pr_url + '" target="_blank" style="color:var(--green)">PR opened →</a></div>' : '') + '</div>';
    }).join('');
  }
  if (history.length > 0) {
    const maxH = 90;
    document.getElementById('chartBars').innerHTML = '<div class="chart-baseline"></div>' +
      history.map(h => {
        const pct = (h.score / 100) * maxH;
        const color = h.score === 100 ? '#1D9E75' : h.score >= 70 ? '#f59e0b' : '#ef4444';
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


def serve(host: str = "127.0.0.1", port: int = 8080):
    import uvicorn
    print(f"\n  CloudCompliance Dashboard")
    print(f"  Running at http://{host}:{port}")
    print(f"  Auto-refreshes every 30 seconds")
    print(f"  Press Ctrl+C to stop\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")
