package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/vardhan/qcore/pkg/model"
)

// PrintTerminalSummary prints a formatted executive summary to the given writer.
func PrintTerminalSummary(w io.Writer, report *model.ScanReport) {
	divider := strings.Repeat("─", 78)
	doubleDivider := strings.Repeat("═", 78)

	fmt.Fprintln(w, doubleDivider)
	fmt.Fprintln(w, "   VARDHAN Q-CORE :: QUANTUM-SAFE CRYPTOGRAPHIC DISCOVERY & CBOM")
	fmt.Fprintln(w, doubleDivider)
	fmt.Fprintf(w, " Target Directory: %s\n", report.Metadata.TargetDirectory)
	fmt.Fprintf(w, " Files Scanned:    %d   | Duration: %d ms | Rules Evaluated: %d\n",
		report.Metadata.FilesScanned, report.Metadata.DurationMs, report.Metadata.RulesLoaded)
	fmt.Fprintln(w, divider)

	// High Level Risk KPI
	fmt.Fprintln(w, " EXECUTIVE RISK SUMMARY")
	fmt.Fprintf(w, "  • Total Discovered Assets:        %d\n", len(report.Assets))
	fmt.Fprintf(w, "  • Quantum-Vulnerable Usages:      %d  [ACTION REQUIRED]\n", report.Summary.QuantumVulnerableCount)
	fmt.Fprintf(w, "  • Weak / Deprecated Classical:    %d\n", report.Summary.WeakClassicalCount)
	fmt.Fprintf(w, "  • Quantum-Ready / Hybrid (PQC):   %d  [COMPLIANT]\n", report.Summary.QuantumReadyCount)
	fmt.Fprintf(w, "  • Max Risk Score:                 %.1f / 100.0\n", report.Summary.MaxRiskScore)
	fmt.Fprintf(w, "  • Average Risk Score:             %.1f / 100.0\n", report.Summary.AverageRiskScore)

	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, " SEVERITY BREAKDOWN")
	fmt.Fprintf(w, "  CRITICAL: %-4d  HIGH: %-4d  MEDIUM: %-4d  LOW: %-4d  INFO: %-4d\n",
		report.Summary.SeverityCounts[string(model.SeverityCritical)],
		report.Summary.SeverityCounts[string(model.SeverityHigh)],
		report.Summary.SeverityCounts[string(model.SeverityMedium)],
		report.Summary.SeverityCounts[string(model.SeverityLow)],
		report.Summary.SeverityCounts[string(model.SeverityInfo)])

	// Findings table preview
	if len(report.Findings) > 0 {
		fmt.Fprintln(w, divider)
		fmt.Fprintln(w, " KEY FINDINGS (TOP PRIORITY)")
		fmt.Fprintf(w, " %-10s %-12s %-25s %-18s %s\n", "SEVERITY", "RISK SCORE", "ALGORITHM / ASSET", "LOCATION", "STATUS")
		fmt.Fprintln(w, strings.Repeat("┄", 78))

		count := 0
		for _, f := range report.Findings {
			if count >= 15 {
				fmt.Fprintf(w, " ... and %d more findings (export CBOM or SARIF for complete audit log)\n", len(report.Findings)-15)
				break
			}
			status := "Quantum-Vulnerable"
			if !f.QuantumVulnerable {
				if f.Category == model.CategoryQuantumReady {
					status = "PQC-Ready"
				} else {
					status = "Weak Classical"
				}
			}

			locStr := fmt.Sprintf("%s:%d", truncateString(f.Location.FilePath, 14), f.Location.StartLine)
			fmt.Fprintf(w, " %-10s %-12.1f %-25s %-18s %s\n",
				f.Severity,
				f.RiskScore,
				truncateString(f.Algorithm, 24),
				locStr,
				status,
			)
			count++
		}
	}

	fmt.Fprintln(w, doubleDivider)
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
