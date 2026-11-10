package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vardhan/qcore/pkg/cbom"
	"github.com/vardhan/qcore/pkg/model"
	"github.com/vardhan/qcore/pkg/reporter"
	"github.com/vardhan/qcore/pkg/rules"
	"github.com/vardhan/qcore/pkg/sarif"
	"github.com/vardhan/qcore/pkg/scanner"
)

var (
	Version   = "0.1.0"
	Commit    = "dev"
	BuildDate = "2026-11-10"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "qcore",
		Short: "Vardhan Q-Core: Quantum-Safe Cryptographic Discovery & CBOM Platform",
		Long: `Vardhan Q-Core is a static cryptographic discovery and migration-planning engine.
It identifies quantum-vulnerable cryptography across source code and dependencies,
computes risk scores based on data lifetime and exposure, and produces audit-ready
CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) and SARIF reports.`,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newScanCmd() *cobra.Command {
	var (
		format        string
		outputFile    string
		rulesDir      string
		failOn        string
		exposure      string
		dataLifetime  string
		projectName   string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or git repository for cryptographic usages and vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}

			absTarget, err := filepath.Abs(targetDir)
			if err != nil {
				return fmt.Errorf("invalid target directory: %w", err)
			}

			// Initialize Rule Engine with bundled rules
			engine, err := rules.NewDefaultEngine()
			if err != nil {
				return fmt.Errorf("failed to load bundled rules: %w", err)
			}

			// Load custom rules if specified
			if rulesDir != "" {
				if err := engine.LoadFromDir(rulesDir); err != nil {
					return fmt.Errorf("failed to load custom rules from %s: %w", rulesDir, err)
				}
			}

			// Setup Risk Configuration
			riskCfg := model.DefaultRiskConfig()
			switch exposure {
			case "internet":
				riskCfg.ExposureFactor = 1.5
			case "internal":
				riskCfg.ExposureFactor = 1.0
			case "offline":
				riskCfg.ExposureFactor = 0.7
			}

			switch dataLifetime {
			case "long": // > 10 years (high HNDL risk)
				riskCfg.DataLifetimeFactor = 1.8
			case "medium": // 1-10 years
				riskCfg.DataLifetimeFactor = 1.2
			case "short": // < 1 year
				riskCfg.DataLifetimeFactor = 0.6
			}

			sc := scanner.NewScanner(engine, Version)
			sc.SetRiskConfig(riskCfg)

			report, err := sc.ScanDirectory(absTarget)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Format and render results
			var outputBytes []byte
			switch format {
			case "cbom":
				if projectName == "" {
					projectName = filepath.Base(absTarget)
				}
				cbomDoc, err := cbom.GenerateCBOM(report, projectName)
				if err != nil {
					return fmt.Errorf("failed to generate CBOM: %w", err)
				}
				outputBytes, err = cbom.ToJSON(cbomDoc)
				if err != nil {
					return fmt.Errorf("failed to serialize CBOM: %w", err)
				}

			case "sarif":
				sarifDoc, err := sarif.GenerateSARIF(report)
				if err != nil {
					return fmt.Errorf("failed to generate SARIF: %w", err)
				}
				outputBytes, err = sarif.ToJSON(sarifDoc)
				if err != nil {
					return fmt.Errorf("failed to serialize SARIF: %w", err)
				}

			case "json":
				outputBytes, err = json.MarshalIndent(report, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to serialize JSON report: %w", err)
				}

			case "table":
				fallthrough
			default:
				if outputFile != "" {
					file, err := os.Create(outputFile)
					if err != nil {
						return fmt.Errorf("failed to create output file: %w", err)
					}
					defer file.Close()
					reporter.PrintTerminalSummary(file, report)
					fmt.Printf("Executive report written to %s\n", outputFile)
				} else {
					reporter.PrintTerminalSummary(os.Stdout, report)
				}
				checkFailPolicy(report, failOn)
				return nil
			}

			// Write structured output (JSON / CBOM / SARIF)
			if outputFile != "" {
				if err := os.WriteFile(outputFile, outputBytes, 0644); err != nil {
					return fmt.Errorf("failed writing output to %s: %w", outputFile, err)
				}
				fmt.Printf("Output written to %s (%s format)\n", outputFile, format)
			} else {
				fmt.Println(string(outputBytes))
			}

			checkFailPolicy(report, failOn)
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, cbom (CycloneDX 1.6), sarif (GitHub Code Scanning), json")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Path to write report output")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "Directory containing additional custom YAML rules")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Fail CI with exit code 1 if threshold met: 'quantum-vulnerable', 'critical', 'high', 'any'")
	cmd.Flags().StringVar(&exposure, "exposure", "internet", "Asset exposure factor: 'internet' (1.5), 'internal' (1.0), 'offline' (0.7)")
	cmd.Flags().StringVar(&dataLifetime, "data-lifetime", "medium", "Confidentiality lifetime factor: 'long' (>10y), 'medium' (1-10y), 'short' (<1y)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "Project name for CBOM metadata")

	return cmd
}

func checkFailPolicy(report *model.ScanReport, policy string) {
	if policy == "" {
		return
	}
	shouldFail := false
	switch policy {
	case "quantum-vulnerable":
		shouldFail = report.Summary.QuantumVulnerableCount > 0
	case "critical":
		shouldFail = report.Summary.SeverityCounts[string(model.SeverityCritical)] > 0
	case "high":
		shouldFail = report.Summary.SeverityCounts[string(model.SeverityCritical)] > 0 ||
			report.Summary.SeverityCounts[string(model.SeverityHigh)] > 0
	case "any":
		shouldFail = report.Summary.TotalFindings > 0
	}

	if shouldFail {
		fmt.Fprintf(os.Stderr, "\n[CI POLICY FAILURE] Scan failed because '%s' threshold was exceeded.\n", policy)
		os.Exit(1)
	}
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and test cryptographic detection rules",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all active detection rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := rules.NewDefaultEngine()
			if err != nil {
				return err
			}
			fmt.Printf("Loaded %d detection rules:\n\n", engine.Count())
			fmt.Printf("%-24s %-12s %-10s %-30s %s\n", "RULE ID", "LANGUAGE", "SEVERITY", "ALGORITHM", "PQC STATUS")
			fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────")
			for _, r := range engine.Rules() {
				pqcStatus := "Vulnerable"
				if !r.Finding.QuantumVulnerable {
					if r.Finding.Category == model.CategoryQuantumReady {
						pqcStatus = "Quantum-Safe"
					} else {
						pqcStatus = "Weak Classical"
					}
				}
				fmt.Printf("%-24s %-12s %-10s %-30s %s\n",
					r.ID, r.Language, r.Finding.Severity, r.Finding.Algorithm, pqcStatus)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Execute positive and negative unit test fixtures for all rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := rules.NewDefaultEngine()
			if err != nil {
				return err
			}
			res := engine.TestAllRules()
			if len(res.Failures) > 0 {
				fmt.Println(res.String())
				os.Exit(1)
			}
			fmt.Println(res.String())
			return nil
		},
	})

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, build metadata, and standard support",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Vardhan Q-Core CLI v%s (%s, built %s)\n", Version, Commit, BuildDate)
			fmt.Println("Standards Compliance:")
			fmt.Println("  • CycloneDX CBOM: Specification v1.6 (Cryptographic Bill of Materials)")
			fmt.Println("  • SARIF Output:   OASIS SARIF v2.1.0 (GitHub Code Scanning)")
			fmt.Println("  • PQC Target:     NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)")
			fmt.Println("  • Security Baseline: CNSA 2.0 / NIST SP 800-131A Rev 2")
		},
	}
}
