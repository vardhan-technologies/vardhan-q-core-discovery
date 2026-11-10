package reporter

import (
	"encoding/json"
	"html/template"
	"io"

	"github.com/vardhan/qcore/pkg/cbom"
	"github.com/vardhan/qcore/pkg/model"
)

type DashboardData struct {
	Report        *model.ScanReport
	AttestationID string
	FindingsJSON  template.JS
	SummaryJSON   template.JS
	CBOMJSON      template.JS
}

const luxuryDashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vardhan Q-Core :: Institutional Post-Quantum Audit & CBOM Platform</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,700;1,400&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #06080F;
      --bg-surface: #0B0F19;
      --card-bg: rgba(17, 24, 39, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --card-hover: rgba(255, 255, 255, 0.12);
      
      --text-primary: #F9FAFB;
      --text-secondary: #9CA3AF;
      --text-tertiary: #6B7280;
      
      --accent-blue: #3B82F6;
      --accent-cyan: #06B6D4;
      --accent-indigo: #6366F1;
      --accent-purple: #8B5CF6;
      --status-red: #EF4444;
      --status-amber: #F59E0B;
      --status-emerald: #10B981;
      
      --font-sans: 'Plus Jakarta Sans', -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      background: radial-gradient(circle at 50% 0%%, #111827 0%%, var(--bg-base) 70%%);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      padding: 32px 48px;
      overflow-x: hidden;
    }

    /* Ambient glow elements */
    .ambient-glow {
      position: fixed;
      top: -200px;
      left: 50%%;
      transform: translateX(-50%%);
      width: 800px;
      height: 400px;
      background: radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%%, rgba(139, 92, 246, 0.05) 50%%, transparent 80%%);
      filter: blur(80px);
      pointer-events: none;
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 1440px;
      margin: 0 auto;
    }

    /* Header Bar */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 28px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 32px;
    }

    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 18px;
    }

    .shield-badge {
      position: relative;
      width: 52px;
      height: 52px;
      background: linear-gradient(135deg, #1E40AF, #7C3AED);
      border-radius: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 24px;
      box-shadow: 0 0 30px rgba(59, 130, 246, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.2);
    }

    .brand-meta h1 {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .badge-institutional {
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.08em;
      padding: 3px 10px;
      border-radius: 9999px;
      background: rgba(99, 102, 241, 0.15);
      color: #A5B4FC;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    .brand-meta p {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 3px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .attestation-seal {
      display: flex;
      align-items: center;
      gap: 10px;
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.25);
      padding: 8px 16px;
      border-radius: 10px;
      font-size: 12px;
      color: #34D399;
      font-family: var(--font-mono);
      box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
    }

    .live-dot {
      width: 8px;
      height: 8px;
      background: var(--status-emerald);
      border-radius: 50%%;
      box-shadow: 0 0 10px var(--status-emerald);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%% { transform: scale(0.95); opacity: 0.8; }
      50%% { transform: scale(1.25); opacity: 1; }
      100%% { transform: scale(0.95); opacity: 0.8; }
    }

    /* KPI Highlights */
    .kpi-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      margin-bottom: 32px;
    }

    .kpi-box {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      position: relative;
      transition: border-color 0.2s, transform 0.2s;
    }

    .kpi-box:hover {
      border-color: var(--card-hover);
      transform: translateY(-2px);
    }

    .kpi-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .kpi-heading {
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.07em;
      color: var(--text-secondary);
    }

    .kpi-num {
      font-size: 38px;
      font-weight: 800;
      letter-spacing: -0.04em;
      line-height: 1;
    }

    .kpi-sub {
      font-size: 12px;
      color: var(--text-tertiary);
      margin-top: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    /* Navigation Tabs */
    .tab-bar {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 28px;
      padding-bottom: 8px;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 600;
      padding: 10px 18px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }

    .tab-btn:hover {
      color: var(--text-primary);
      background: rgba(255, 255, 255, 0.04);
    }

    .tab-btn.active {
      color: #93C5FD;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
    }

    /* Tab Content Panes */
    .tab-pane {
      display: none;
    }
    .tab-pane.active {
      display: block;
    }

    /* Overview Grid */
    .overview-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
    }

    .panel {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 28px;
      margin-bottom: 24px;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .panel-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* Threat Horizon & Gauge */
    .gauge-wrapper {
      display: flex;
      align-items: center;
      gap: 32px;
      padding: 16px 0;
    }

    .gauge-svg {
      width: 140px;
      height: 140px;
      transform: rotate(-90deg);
    }

    .gauge-bg {
      fill: none;
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 12;
    }

    .gauge-fill {
      fill: none;
      stroke: url(#gaugeGradient);
      stroke-width: 12;
      stroke-linecap: round;
      transition: stroke-dashoffset 1s ease-in-out;
    }

    .gauge-details h3 {
      font-size: 24px;
      font-weight: 800;
    }

    .gauge-details p {
      font-size: 13px;
      color: var(--text-secondary);
      max-width: 440px;
      margin-top: 4px;
    }

    /* HNDL Timeline Bar */
    .timeline-card {
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 18px;
      margin-top: 20px;
    }

    .timeline-title {
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #F87171;
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
    }

    .timeline-track {
      height: 10px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 9999px;
      position: relative;
      overflow: hidden;
      margin-bottom: 8px;
    }

    .timeline-progress {
      height: 100%%;
      width: 72%%;
      background: linear-gradient(90deg, #10B981, #F59E0B, #EF4444);
      border-radius: 9999px;
    }

    .timeline-labels {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--text-tertiary);
      font-family: var(--font-mono);
    }

    /* Standards list */
    .compliance-stack {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .compliance-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .comp-name {
      font-size: 13px;
      font-weight: 700;
    }

    .comp-desc {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .status-pill {
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
      padding: 4px 10px;
      border-radius: 6px;
    }

    .pill-compliant { background: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .pill-action { background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .pill-warning { background: rgba(245, 158, 11, 0.15); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.3); }

    /* Filter & Search Bar */
    .search-filter-bar {
      display: flex;
      gap: 16px;
      margin-bottom: 20px;
      align-items: center;
    }

    .search-input {
      flex: 1;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 12px 18px;
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }

    .search-input:focus {
      border-color: var(--accent-blue);
      box-shadow: 0 0 10px rgba(59, 130, 246, 0.2);
    }

    .filter-pills {
      display: flex;
      gap: 8px;
    }

    .fpill {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      color: var(--text-secondary);
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }

    .fpill.active {
      background: rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.4);
      color: #93C5FD;
    }

    /* Findings Table */
    .table-container {
      overflow-x: auto;
      border-radius: 12px;
      border: 1px solid var(--card-border);
    }

    table {
      width: 100%%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }

    th {
      background: rgba(255, 255, 255, 0.02);
      padding: 14px 18px;
      color: var(--text-secondary);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      border-bottom: 1px solid var(--card-border);
    }

    td {
      padding: 16px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
    }

    tr.finding-row:hover {
      background: rgba(255, 255, 255, 0.02);
      cursor: pointer;
    }

    .badge-sev {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
    }

    .sev-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.4); }
    .sev-HIGH { background: rgba(249, 115, 22, 0.2); color: #FDBA74; border: 1px solid rgba(249, 115, 22, 0.4); }
    .sev-MEDIUM { background: rgba(245, 158, 11, 0.2); color: #FDE047; border: 1px solid rgba(245, 158, 11, 0.4); }
    .sev-INFO { background: rgba(16, 185, 129, 0.2); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.4); }

    .algo-pill {
      font-family: var(--font-mono);
      font-weight: 700;
      color: #F3F4F6;
    }

    .loc-tag {
      font-family: var(--font-mono);
      font-size: 12px;
      color: #93C5FD;
      background: rgba(59, 130, 246, 0.08);
      padding: 3px 8px;
      border-radius: 6px;
      border: 1px solid rgba(59, 130, 246, 0.2);
    }

    /* JSON code block */
    pre.raw-json {
      background: #04060A;
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #93C5FD;
      overflow-x: auto;
      max-height: 600px;
    }

    .copy-btn {
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #93C5FD;
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      float: right;
      margin-bottom: 12px;
    }
    .copy-btn:hover {
      background: rgba(59, 130, 246, 0.25);
    }
  </style>
</head>
<body>

  <div class="ambient-glow"></div>

  <div class="container">
    
    <!-- Header -->
    <header>
      <div class="brand-wrap">
        <div class="shield-badge">Q</div>
        <div class="brand-meta">
          <h1>
            Vardhan Q-Core
            <span class="badge-institutional">Institutional Discovery & CBOM</span>
          </h1>
          <p>Target: <code style="color:#93C5FD">{{ .Report.Metadata.TargetDirectory }}</code> &bull; Scanned {{ .Report.Metadata.FilesScanned }} files in {{ .Report.Metadata.DurationMs }} ms &bull; CycloneDX 1.6 Cryptographic Specification</p>
        </div>
      </div>
      <div class="header-actions">
        <div class="attestation-seal">
          <div class="live-dot"></div>
          Ed25519 Certified: {{ .AttestationID }}
        </div>
      </div>
    </header>

    <!-- KPI Row -->
    <div class="kpi-row">
      <div class="kpi-box">
        <div class="kpi-top">
          <span class="kpi-heading">Quantum-Vulnerable</span>
          <span class="status-pill pill-action">Action Required</span>
        </div>
        <div class="kpi-num" style="color:var(--status-red)">{{ .Report.Summary.QuantumVulnerableCount }}</div>
        <div class="kpi-sub">Shor's Algorithm Factoring Vulnerabilities</div>
      </div>

      <div class="kpi-box">
        <div class="kpi-top">
          <span class="kpi-heading">Weak Classical</span>
          <span class="status-pill pill-warning">Deprecated</span>
        </div>
        <div class="kpi-num" style="color:var(--status-amber)">{{ .Report.Summary.WeakClassicalCount }}</div>
        <div class="kpi-sub">Broken Hashing & Weak Symmetric Ciphers</div>
      </div>

      <div class="kpi-box">
        <div class="kpi-top">
          <span class="kpi-heading">PQC Compliant</span>
          <span class="status-pill pill-compliant">Certified Ready</span>
        </div>
        <div class="kpi-num" style="color:var(--status-emerald)">{{ .Report.Summary.QuantumReadyCount }}</div>
        <div class="kpi-sub">NIST FIPS 203/204 & Hybrid ML-KEM</div>
      </div>

      <div class="kpi-box">
        <div class="kpi-top">
          <span class="kpi-heading">Max Risk Score</span>
          <span class="status-pill" style="background:rgba(59,130,246,0.15);color:#93C5FD">Calibrated</span>
        </div>
        <div class="kpi-num" style="color:var(--accent-blue)">{{ printf "%.1f" .Report.Summary.MaxRiskScore }}<span style="font-size:18px;color:var(--text-tertiary)">/100</span></div>
        <div class="kpi-sub">Avg Portfolio Score: {{ printf "%.1f" .Report.Summary.AverageRiskScore }} / 100.0</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('overview')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>
        Executive Summary
      </button>
      <button class="tab-btn" onclick="switchTab('cbom')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" x2="12" y1="22.08" y2="12"/></svg>
        CBOM Inventory Explorer (CycloneDX 1.6)
      </button>
      <button class="tab-btn" onclick="switchTab('raw-cbom')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        Raw CBOM JSON Export
      </button>
    </div>

    <!-- TAB 1: EXECUTIVE OVERVIEW -->
    <div id="tab-overview" class="tab-pane active">
      <div class="overview-grid">
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              Cryptographic Threat Horizon & HNDL Exposure
            </div>
          </div>

          <div class="gauge-wrapper">
            <svg class="gauge-svg" viewBox="0 0 100 100">
              <defs>
                <linearGradient id="gaugeGradient" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
                  <stop offset="0%%" stop-color="#10B981" />
                  <stop offset="50%%" stop-color="#F59E0B" />
                  <stop offset="100%%" stop-color="#EF4444" />
                </linearGradient>
              </defs>
              <circle class="gauge-bg" cx="50" cy="50" r="40" />
              <circle class="gauge-fill" cx="50" cy="50" r="40" stroke-dasharray="251.2" stroke-dashoffset="{{ calculateDashOffset .Report.Summary.MaxRiskScore }}" />
            </svg>
            <div class="gauge-details">
              <h3>Score: {{ printf "%.1f" .Report.Summary.MaxRiskScore }} / 100</h3>
              <p>Risk index computed via Vulnerability Class Weight &times; Data Lifetime Factor &times; Exposure Factor &times; Migration Difficulty.</p>
            </div>
          </div>

          <div class="timeline-card">
            <div class="timeline-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              Harvest-Now-Decrypt-Later (HNDL) Threat Window
            </div>
            <div class="timeline-track">
              <div class="timeline-progress"></div>
            </div>
            <div class="timeline-labels">
              <span>2024: Interception Window</span>
              <span>2026: NIST FIPS Active</span>
              <span style="color:#F87171">2030: CNSA 2.0 / Q-Day Horizon</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Regulatory Posture
            </div>
          </div>
          <div class="compliance-stack">
            <div class="compliance-item">
              <div>
                <div class="comp-name">NIST FIPS 203 (ML-KEM)</div>
                <div class="comp-desc">Key-Encapsulation Mechanism</div>
              </div>
              <span class="status-pill pill-compliant">Mandate</span>
            </div>
            <div class="compliance-item">
              <div>
                <div class="comp-name">NIST FIPS 204 (ML-DSA)</div>
                <div class="comp-desc">Lattice Digital Signatures</div>
              </div>
              <span class="status-pill pill-compliant">Mandate</span>
            </div>
            <div class="compliance-item">
              <div>
                <div class="comp-name">EU DORA (Reg 2022/2554)</div>
                <div class="comp-desc">ICT Operational Resilience</div>
              </div>
              <span class="status-pill pill-warning">Enforced</span>
            </div>
            <div class="compliance-item">
              <div>
                <div class="comp-name">NSA CNSA 2.0</div>
                <div class="comp-desc">Commercial National Security</div>
              </div>
              <span class="status-pill pill-action">2030 Gate</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: CBOM INVENTORY EXPLORER -->
    <div id="tab-cbom" class="tab-pane">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#60A5FA" stroke-width="2"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>
            Cryptographic Bill of Materials (CBOM) & Triage
          </div>
          <span style="font-size:12px;color:var(--text-secondary)">{{ len .Report.Findings }} Verified Usages</span>
        </div>

        <div class="search-filter-bar">
          <input type="text" id="cbomSearch" class="search-input" placeholder="Search by algorithm, file, library, or category..." onkeyup="filterCBOM()">
          <div class="filter-pills">
            <button class="fpill active" onclick="setCategoryFilter('ALL', this)">All</button>
            <button class="fpill" onclick="setCategoryFilter('quantum-vulnerable-public-key', this)">Vulnerable</button>
            <button class="fpill" onclick="setCategoryFilter('weak-classical-cryptography', this)">Weak Classical</button>
            <button class="fpill" onclick="setCategoryFilter('quantum-ready-pqc', this)">PQC Ready</button>
          </div>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Risk</th>
                <th>Algorithm</th>
                <th>Location</th>
                <th>Prescriptive Remediation Target</th>
              </tr>
            </thead>
            <tbody id="cbomTableBody">
              {{ range .Report.Findings }}
              <tr class="finding-row" data-cat="{{ .Category }}" data-algo="{{ .Algorithm }}" data-file="{{ .Location.FilePath }}">
                <td><span class="badge-sev sev-{{ .Severity }}">{{ .Severity }}</span></td>
                <td style="font-weight:700;font-family:var(--font-mono)">{{ printf "%.1f" .RiskScore }}</td>
                <td><span class="algo-pill">{{ .Algorithm }}</span></td>
                <td><span class="loc-tag">{{ .Location.FilePath }}:{{ .Location.StartLine }}</span></td>
                <td style="color:var(--text-secondary);font-size:12px">{{ .Remediation }}</td>
              </tr>
              {{ end }}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: RAW CBOM JSON -->
    <div id="tab-raw-cbom" class="tab-pane">
      <div class="panel">
        <button class="copy-btn" onclick="copyCBOM()">Copy CycloneDX 1.6 JSON</button>
        <div class="panel-header">
          <div class="panel-title">CycloneDX 1.6 Cryptographic Bill of Materials (JSON)</div>
        </div>
        <pre class="raw-json" id="cbomCodeBlock">{{ .CBOMJSON }}</pre>
      </div>
    </div>

  </div>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById('tab-' + tabId).classList.add('active');
      event.currentTarget.classList.add('active');
    }

    let activeCategory = 'ALL';

    function setCategoryFilter(cat, btn) {
      activeCategory = cat;
      document.querySelectorAll('.fpill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterCBOM();
    }

    function filterCBOM() {
      const q = document.getElementById('cbomSearch').value.toLowerCase();
      const rows = document.querySelectorAll('.finding-row');
      rows.forEach(r => {
        const cat = r.getAttribute('data-cat') || '';
        const algo = r.getAttribute('data-algo') || '';
        const file = r.getAttribute('data-file') || '';
        const matchesQuery = algo.toLowerCase().includes(q) || file.toLowerCase().includes(q);
        const matchesCategory = (activeCategory === 'ALL') || (cat === activeCategory);
        r.style.display = (matchesQuery && matchesCategory) ? '' : 'none';
      });
    }

    function copyCBOM() {
      const text = document.getElementById('cbomCodeBlock').innerText;
      navigator.clipboard.writeText(text).then(() => {
        alert('CycloneDX 1.6 CBOM JSON copied to clipboard!');
      });
    }
  </script>
</body>
</html>`

func calculateDashOffset(riskScore float64) float64 {
	// Circumference = 2 * PI * r = 2 * 3.14159 * 40 = 251.2
	circumference := 251.2
	ratio := riskScore / 100.0
	if ratio > 1.0 {
		ratio = 1.0
	}
	if ratio < 0.0 {
		ratio = 0.0
	}
	return circumference * (1.0 - ratio)
}

func GenerateHTMLDashboard(w io.Writer, report *model.ScanReport, attestationID string) error {
	if attestationID == "" {
		attestationID = "Self-Verified"
	}

	cbomDoc, _ := cbom.GenerateCBOM(report, report.Metadata.TargetDirectory)
	cbomBytes, _ := cbom.ToJSON(cbomDoc)
	findingsBytes, _ := json.Marshal(report.Findings)
	summaryBytes, _ := json.Marshal(report.Summary)

	funcMap := template.FuncMap{
		"calculateDashOffset": calculateDashOffset,
	}

	tmpl, err := template.New("luxury_dashboard").Funcs(funcMap).Parse(luxuryDashboardTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(w, DashboardData{
		Report:        report,
		AttestationID: attestationID,
		FindingsJSON:  template.JS(string(findingsBytes)),
		SummaryJSON:   template.JS(string(summaryBytes)),
		CBOMJSON:      template.JS(string(cbomBytes)),
	})
}
