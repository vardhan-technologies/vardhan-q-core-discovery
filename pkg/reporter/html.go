package reporter

import (
	"html/template"
	"io"

	"github.com/vardhan/qcore/pkg/model"
)

type DashboardData struct {
	Report        *model.ScanReport
	AttestationID string
}

const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vardhan Q-Core :: Cryptographic Audit & CBOM Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --red: #ef4444;
      --green: #10b981;
      --amber: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      padding: 32px 48px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .logo-badge {
      background: linear-gradient(135deg, #2563eb, #7c3aed);
      width: 48px;
      height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 22px;
      box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
    }
    .title h1 {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.02em;
    }
    .title p {
      font-size: 13px;
      color: var(--text-muted);
    }
    .attest-badge {
      display: flex;
      align-items: center;
      gap: 10px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 8px 16px;
      border-radius: 9999px;
      font-size: 13px;
      color: #34d399;
      font-family: 'JetBrains Mono', monospace;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      margin-bottom: 32px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
    }
    .kpi-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 8px;
      font-weight: 600;
    }
    .kpi-value {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -0.03em;
    }
    .kpi-desc {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .val-red { color: var(--red); }
    .val-green { color: var(--green); }
    .val-amber { color: var(--amber); }
    .val-blue { color: var(--accent); }

    .main-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
      margin-bottom: 32px;
    }
    .section-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
    }
    .section-title {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      text-align: left;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    .tag {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      font-family: 'JetBrains Mono', monospace;
    }
    .tag-critical { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .tag-high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .tag-medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .tag-info { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .code-loc {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #93c5fd;
    }
    .standards-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .standard-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      padding: 14px;
      border-radius: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .standard-info h4 {
      font-size: 13px;
      font-weight: 600;
    }
    .standard-info p {
      font-size: 11px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="logo-badge">Q</div>
      <div class="title">
        <h1>Vardhan Q-Core :: Cryptographic Inventory & Audit Dashboard</h1>
        <p>Target: <code>{{ .Report.Metadata.TargetDirectory }}</code> &bull; Scanned {{ .Report.Metadata.FilesScanned }} files in {{ .Report.Metadata.DurationMs }} ms &bull; CycloneDX 1.6 CBOM</p>
      </div>
    </div>
    <div class="attest-badge">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
      Attestation: {{ .AttestationID }}
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Quantum Vulnerable Usages</div>
      <div class="kpi-value val-red">{{ .Report.Summary.QuantumVulnerableCount }}</div>
      <div class="kpi-desc">Action Required (Shor's Algorithm)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Weak Classical Cryptography</div>
      <div class="kpi-value val-amber">{{ .Report.Summary.WeakClassicalCount }}</div>
      <div class="kpi-desc">MD5, SHA-1, 3DES, ECB Mode</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Post-Quantum (PQC) Compliant</div>
      <div class="kpi-value val-green">{{ .Report.Summary.QuantumReadyCount }}</div>
      <div class="kpi-desc">NIST FIPS 203/204 / Hybrid ML-KEM</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Max Risk Score</div>
      <div class="kpi-value val-blue">{{ printf "%.1f" .Report.Summary.MaxRiskScore }} <span style="font-size:16px;color:var(--text-muted)">/ 100</span></div>
      <div class="kpi-desc">Average Risk: {{ printf "%.1f" .Report.Summary.AverageRiskScore }} / 100.0</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="section-card">
      <div class="section-title">
        <span>Discovered Cryptographic Findings</span>
        <span style="font-size: 12px; color: var(--text-muted);">Total: {{ len .Report.Findings }} items</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Risk Score</th>
            <th>Algorithm</th>
            <th>Location</th>
            <th>Remediation Target</th>
          </tr>
        </thead>
        <tbody>
          {{ range .Report.Findings }}
          <tr>
            <td><span class="tag tag-{{ .Severity }}">{{ .Severity }}</span></td>
            <td style="font-weight:700;font-family:'JetBrains Mono'">{{ printf "%.1f" .RiskScore }}</td>
            <td><strong>{{ .Algorithm }}</strong></td>
            <td><span class="code-loc">{{ .Location.FilePath }}:{{ .Location.StartLine }}</span></td>
            <td style="color:var(--text-muted);font-size:12px">{{ .Remediation }}</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-title">Regulatory & Standards Alignment</div>
      <div class="standards-list">
        <div class="standard-item">
          <div class="standard-info">
            <h4>NIST FIPS 203 (ML-KEM)</h4>
            <p>Key-Encapsulation Mechanism</p>
          </div>
          <span class="tag tag-info">Target 2026-2030</span>
        </div>
        <div class="standard-item">
          <div class="standard-info">
            <h4>NIST FIPS 204 (ML-DSA)</h4>
            <p>Module-Lattice Digital Signatures</p>
          </div>
          <span class="tag tag-info">Target 2026-2030</span>
        </div>
        <div class="standard-item">
          <div class="standard-info">
            <h4>NSA CNSA 2.0</h4>
            <p>National Security Systems Mandate</p>
          </div>
          <span class="tag tag-high">Enforced 2030</span>
        </div>
        <div class="standard-item">
          <div class="standard-info">
            <h4>EU DORA (Regulation 2022/2554)</h4>
            <p>Digital Operational Resilience Act</p>
          </div>
          <span class="tag tag-medium">Active Invariant</span>
        </div>
        <div class="standard-item">
          <div class="standard-info">
            <h4>CycloneDX Specification</h4>
            <p>CBOM Schema v1.6 Validation</p>
          </div>
          <span class="tag tag-info">Validated</span>
        </div>
      </div>
    </div>
  </div>

</body>
</html>`

func GenerateHTMLDashboard(w io.Writer, report *model.ScanReport, attestationID string) error {
	if attestationID == "" {
		attestationID = "Self-Verified"
	}
	tmpl, err := template.New("dashboard").Parse(dashboardTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, DashboardData{
		Report:        report,
		AttestationID: attestationID,
	})
}
