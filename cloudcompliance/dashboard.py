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

BASE = Path(__file__).parent.parent
COMPLIANCE_DIR = BASE / "compliance"

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
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--green:#1D9E75;--bg:#0f1117;--surface:#1a1d27;--surface2:#222536;--border:#2a2d3e;--text:#e2e8f0;--muted:#8892a4;--mono:'Fira Code',monospace}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
nav{display:flex;justify-content:space-between;align-items:center;padding:1rem 2rem;border-bottom:1px solid var(--border);background:var(--bg)}
.logo{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:600}
.logo-icon{width:32px;height:32px;background:var(--green);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px;font-weight:700}
.nav-right{display:flex;align-items:center;gap:12px}
.live-dot{width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.last-updated{font-size:12px;color:var(--muted)}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.grid-top{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:2rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem}
.card-label{font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em}
.card-value{font-size:36px;font-weight:700}
.card-sub{font-size:13px;color:var(--muted);margin-top:4px}
.score-ring{position:relative;width:120px;height:120px;margin:0 auto 1rem}
.ring-bg{fill:none;stroke:var(--border);stroke-width:8}
.ring-fill{fill:none;stroke-width:8;stroke-linecap:round;transform:rotate(-90deg);transform-origin:60px 60px;transition:stroke-dashoffset 1s ease}
.ring-text{font-size:18px;font-weight:700;fill:var(--text)}
.ring-sub{font-size:11px;fill:var(--muted)}
.score-card{text-align:center;padding:2rem}
.grid-mid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:2rem}
.controls-list{display:flex;flex-direction:column;gap:8px}
.control-row{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--surface2);border-radius:8px}
.control-id{font-family:var(--mono);font-size:12px;color:var(--green);width:50px}
.control-title{font-size:13px;flex:1;margin:0 12px}
.control-status{font-size:12px;padding:2px 8px;border-radius:10px}
.pass{background:rgba(74,222,128,0.1);color:#4ade80}
.partial{background:rgba(251,191,36,0.1);color:#fbbf24}
.fail{background:rgba(248,113,113,0.1);color:#f87171}
.drift-card{}
.drift-empty{text-align:center;padding:2rem;color:var(--muted);font-size:14px}
.finding-row{padding:10px 14px;background:var(--surface2);border-radius:8px;margin-bottom:8px}
.finding-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.finding-resource{font-family:var(--mono);font-size:12px;color:var(--text)}
.finding-type{font-size:11px;padding:2px 6px;border-radius:6px}
.high{background:rgba(251,191,36,0.1);color:#fbbf24}
.critical{background:rgba(248,113,113,0.1);color:#f87171}
.medium{background:rgba(125,211,252,0.1);color:#7dd3fc}
.finding-desc{font-size:12px;color:var(--muted)}
.history-section{margin-bottom:2rem}
.chart{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem}
.chart-title{font-size:14px;font-weight:600;margin-bottom:1rem}
.chart-bars{display:flex;align-items:flex-end;gap:4px;height:120px}
.bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.bar{width:100%;border-radius:4px 4px 0 0;transition:height 0.5s ease;min-height:4px;cursor:pointer}
.bar-label{font-size:9px;color:var(--muted);text-align:center}
.bar-val{font-size:10px;color:var(--text);text-align:center}
.remediation-card{margin-bottom:2rem}
.pr-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--surface2);border-radius:8px;margin-bottom:8px}
.pr-resource{font-family:var(--mono);font-size:12px}
.pr-link{font-size:12px;color:var(--green)}
.section-title{font-size:16px;font-weight:600;margin-bottom:1rem}
.badge-row{display:flex;gap:8px;margin-bottom:2rem;flex-wrap:wrap}
.badge{padding:4px 12px;border-radius:20px;font-size:12px;border:1px solid var(--border);color:var(--muted)}
.badge.green{background:rgba(74,222,128,0.1);border-color:rgba(74,222,128,0.3);color:#4ade80}
.badge.yellow{background:rgba(251,191,36,0.1);border-color:rgba(251,191,36,0.3);color:#fbbf24}
.badge.red{background:rgba(248,113,113,0.1);border-color:rgba(248,113,113,0.3);color:#f87171}
@media(max-width:768px){.grid-top{grid-template-columns:repeat(2,1fr)}.grid-mid{grid-template-columns:1fr}}
</style>
</head>
<body>

<nav>
  <div class="logo">
    <div class="logo-icon">CC</div>
    CloudCompliance Dashboard
  </div>
  <div class="nav-right">
    <div class="live-dot"></div>
    <span class="last-updated" id="lastUpdated">Loading...</span>
  </div>
</nav>

<div class="container">

  <div class="badge-row" id="badgeRow"></div>

  <div class="grid-top">
    <div class="card score-card">
      <svg class="score-ring" viewBox="0 0 120 120">
        <circle class="ring-bg" cx="60" cy="60" r="52"/>
        <circle class="ring-fill" id="ringFill" cx="60" cy="60" r="52"
          stroke="#1D9E75"
          stroke-dasharray="326.7"
          stroke-dashoffset="326.7"/>
        <text class="ring-text" x="60" y="56" text-anchor="middle" dominant-baseline="central" id="scoreText">0%</text>
        <text class="ring-sub" x="60" y="72" text-anchor="middle" id="scoreControls">0/0</text>
      </svg>
      <div class="card-label">Compliance Score</div>
    </div>
    <div class="card">
      <div class="card-label">AWS Resources</div>
      <div class="card-value" id="resourceCount">—</div>
      <div class="card-sub">provisioned</div>
    </div>
    <div class="card">
      <div class="card-label">Drift Findings</div>
      <div class="card-value" id="driftCount" style="color:#fbbf24">—</div>
      <div class="card-sub">detected</div>
    </div>
    <div class="card">
      <div class="card-label">Auto-Remediated</div>
      <div class="card-value" id="remediateCount" style="color:#4ade80">—</div>
      <div class="card-sub">PRs opened: <span id="prCount">0</span></div>
    </div>
  </div>

  <div class="grid-mid">
    <div class="card">
      <div class="section-title">SOC2 Controls</div>
      <div class="controls-list" id="controlsList">
        <div style="color:var(--muted);font-size:14px;padding:1rem">Loading controls...</div>
      </div>
    </div>
    <div class="card drift-card">
      <div class="section-title">Drift Findings</div>
      <div id="driftList">
        <div class="drift-empty">No drift detected ✅</div>
      </div>
    </div>
  </div>

  <div class="chart">
    <div class="chart-title">Compliance Score History</div>
    <div class="chart-bars" id="chartBars">
      <div style="color:var(--muted);font-size:13px;align-self:center;margin:0 auto">No history yet — run cloudcompliance report</div>
    </div>
  </div>

  <div id="remediationSection" style="margin-top:1.5rem;display:none">
    <div class="card">
      <div class="section-title">Pull Requests Opened</div>
      <div id="prList"></div>
    </div>
  </div>

</div>

<script>
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    updateDashboard(data);
  } catch(e) {
    console.error('Failed to fetch status:', e);
  }
}

function updateDashboard(data) {
  const { compliance, drift, remediation, history } = data;

  // Last updated
  document.getElementById('lastUpdated').textContent =
    'Updated ' + new Date().toLocaleTimeString();

  // Score ring
  const score = compliance.score || 0;
  const circumference = 326.7;
  const offset = circumference - (score / 100) * circumference;
  document.getElementById('ringFill').style.strokeDashoffset = offset;
  document.getElementById('ringFill').style.stroke =
    score === 100 ? '#1D9E75' : score >= 70 ? '#fbbf24' : '#f87171';
  document.getElementById('scoreText').textContent = score + '%';

  const controls = compliance.controls || {};
  const passing = Object.values(controls).filter(c => c.status === 'PASS').length;
  const total = Object.keys(controls).length;
  document.getElementById('scoreControls').textContent = passing + '/' + total;

  // Stats
  document.getElementById('resourceCount').textContent = compliance.total_resources || '—';
  document.getElementById('driftCount').textContent = drift.count || 0;
  document.getElementById('remediateCount').textContent = remediation.auto_fixed || 0;
  document.getElementById('prCount').textContent = remediation.prs_opened || 0;

  // Badges
  const badges = [
    { label: 'v1.4.0', cls: '' },
    { label: score === 100 ? '✅ Compliant' : '⚠️ Non-compliant', cls: score === 100 ? 'green' : 'yellow' },
    { label: drift.count === 0 ? '✅ No drift' : `⚠️ ${drift.count} drift(s)`, cls: drift.count === 0 ? 'green' : 'yellow' },
    { label: total + ' controls', cls: '' },
  ];
  document.getElementById('badgeRow').innerHTML = badges
    .map(b => `<span class="badge ${b.cls}">${b.label}</span>`).join('');

  // Controls list
  document.getElementById('controlsList').innerHTML = Object.entries(controls)
    .map(([id, ctrl]) => {
      const statusClass = ctrl.status === 'PASS' ? 'pass' : ctrl.status === 'PARTIAL' ? 'partial' : 'fail';
      const statusLabel = ctrl.status === 'PASS' ? '✅ PASS' : ctrl.status === 'PARTIAL' ? '⚠️ PARTIAL' : '❌ FAIL';
      return `<div class="control-row">
        <span class="control-id">${id}</span>
        <span class="control-title">${ctrl.title}</span>
        <span class="control-status ${statusClass}">${statusLabel}</span>
      </div>`;
    }).join('');

  // Drift findings
  const findings = drift.findings || [];
  document.getElementById('driftList').innerHTML = findings.length === 0
    ? '<div class="drift-empty">No drift detected ✅</div>'
    : findings.map(f => `
        <div class="finding-row">
          <div class="finding-header">
            <span class="finding-resource">${f.resource_id}</span>
            <span class="finding-type ${f.severity.toLowerCase()}">${f.severity}</span>
          </div>
          <div class="finding-desc">${f.drift_type} — ${f.description.slice(0, 60)}...</div>
        </div>`).join('');

  // History chart
  if (history.length > 0) {
    const maxScore = 100;
    document.getElementById('chartBars').innerHTML = history.map(h => {
      const pct = (h.score / maxScore) * 100;
      const color = h.score === 100 ? '#1D9E75' : h.score >= 70 ? '#fbbf24' : '#f87171';
      const date = new Date(h.timestamp).toLocaleDateString('en', {month:'short',day:'numeric'});
      return `<div class="bar-wrap">
        <div class="bar-val">${h.score}%</div>
        <div class="bar" style="height:${pct}%;background:${color}" title="${date}: ${h.score}%"></div>
        <div class="bar-label">${date}</div>
      </div>`;
    }).join('');
  }

  // PRs
  const prs = remediation.pull_requests || [];
  if (prs.length > 0) {
    document.getElementById('remediationSection').style.display = 'block';
    document.getElementById('prList').innerHTML = prs.map(pr => `
      <div class="pr-row">
        <span class="pr-resource">${pr.resource}</span>
        <a href="${pr.pr_url}" target="_blank" class="pr-link">View PR →</a>
      </div>`).join('');
  }
}

fetchStatus();
setInterval(fetchStatus, 30000);
</script>
</body>
</html>
"""


def serve(host: str = "127.0.0.1", port: int = 8080):
    import uvicorn
    print(f"\n🛡️  CloudCompliance Dashboard")
    print(f"   Running at http://{host}:{port}")
    print(f"   Auto-refreshes every 30 seconds")
    print(f"   Press Ctrl+C to stop\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")
