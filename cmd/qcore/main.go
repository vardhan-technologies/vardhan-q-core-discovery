package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vardhan/qcore/pkg/attestation"
	"github.com/vardhan/qcore/pkg/baseline"
	"github.com/vardhan/qcore/pkg/benchmark"
	"github.com/vardhan/qcore/pkg/bundle"
	"github.com/vardhan/qcore/pkg/cbom"
	"github.com/vardhan/qcore/pkg/license"
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
	rootCmd.AddCommand(newBenchmarkCmd())
	rootCmd.AddCommand(newKeygenCmd())
	rootCmd.AddCommand(newVerifyCmd())
	rootCmd.AddCommand(newBaselineCmd())
	rootCmd.AddCommand(newLicenseCmd())
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
		baselineFile  string
		signWithKey   string
		issuer        string
		bundleFile    string
		trustedKey    string
		licenseFile   string
		vendorKey     string
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

			// Verify offline license if provided (PRD L-03)
			if licenseFile != "" {
				lic, err := license.Load(licenseFile)
				if err != nil {
					return fmt.Errorf("failed to load offline license: %w", err)
				}
				valid, inGrace, msg := lic.Verify(vendorKey)
				if !valid {
					return fmt.Errorf("offline license verification failed: %s", msg)
				}
				if inGrace {
					fmt.Printf("[LICENSE GRACE] %s\n", msg)
				} else {
					fmt.Printf("[LICENSE VERIFIED] Customer: %s | Tier: %s | Status: Active\n",
						lic.CustomerName, lic.Tier)
				}
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

			// Load signed intelligence bundle if provided (PRD D-04/L-04)
			if bundleFile != "" {
				b, err := bundle.LoadFromFile(bundleFile)
				if err != nil {
					return fmt.Errorf("failed to load capability bundle: %w", err)
				}
				if err := b.Install(engine, trustedKey); err != nil {
					return fmt.Errorf("bundle verification/installation failed: %w", err)
				}
				fmt.Printf("[INTEL] Installed verified offline capability bundle: %s (%s)\n",
					b.BundleVersion, b.Description)
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

			// Apply baseline if provided (PRD F-08)
			if baselineFile != "" {
				bl, err := baseline.Load(baselineFile)
				if err != nil {
					return fmt.Errorf("failed to load baseline %s: %w", baselineFile, err)
				}
				res := bl.Apply(report)
				fmt.Printf("[BASELINE] Reconciled against %s: %d accepted exceptions active, %d expired\n",
					baselineFile, res.ActiveExceptions, res.ExpiredExceptions)
			}

			// Generate CBOM representation
			if projectName == "" {
				projectName = filepath.Base(absTarget)
			}
			cbomDoc, err := cbom.GenerateCBOM(report, projectName)
			if err != nil {
				return fmt.Errorf("failed to generate CBOM: %w", err)
			}
			cbomBytes, err := cbom.ToJSON(cbomDoc)
			if err != nil {
				return fmt.Errorf("failed to serialize CBOM: %w", err)
			}

			reportBytes, _ := json.MarshalIndent(report, "", "  ")

			// Cryptographic Attestation Signing (PRD R-04)
			if signWithKey != "" {
				privKeyRaw, err := os.ReadFile(signWithKey)
				if err != nil {
					return fmt.Errorf("failed reading signing key from %s: %w", signWithKey, err)
				}
				privKeyStr := strings.TrimSpace(string(privKeyRaw))
				att, err := attestation.CreateAttestation(report, reportBytes, cbomBytes, issuer, privKeyStr)
				if err != nil {
					return fmt.Errorf("failed to generate audit attestation: %w", err)
				}
				attBytes, _ := attestation.ToJSON(att)
				attPath := outputFile
				if attPath == "" {
					attPath = "qcore-audit-attestation.json"
				} else {
					attPath = strings.TrimSuffix(attPath, filepath.Ext(attPath)) + ".attestation.json"
				}
				if err := os.WriteFile(attPath, attBytes, 0644); err != nil {
					return fmt.Errorf("failed writing attestation: %w", err)
				}
				fmt.Printf("[ATTESTATION] Signed audit certificate generated at: %s (ID: %s)\n", attPath, att.ID)
			}

			// Format and render results
			var outputBytes []byte
			switch format {
			case "cbom":
				outputBytes = cbomBytes
			case "sarif":
				sarifDoc, err := sarif.GenerateSARIF(report)
				if err != nil {
					return fmt.Errorf("failed to generate SARIF: %w", err)
				}
				outputBytes, err = sarif.ToJSON(sarifDoc)
				if err != nil {
					return fmt.Errorf("failed to serialize SARIF: %w", err)
				}
			case "html":
				var attID string
				if signWithKey != "" {
					attID = "qatt-signed"
				}
				var htmlBuf bytes.Buffer
				if err := reporter.GenerateHTMLDashboard(&htmlBuf, report, attID); err != nil {
					return fmt.Errorf("failed generating HTML dashboard: %w", err)
				}
				outputBytes = htmlBuf.Bytes()

			case "json":
				outputBytes = reportBytes
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

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, cbom (CycloneDX 1.6), sarif (GitHub Code Scanning), json, html")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Path to write report output")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "Directory containing additional custom YAML rules")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Fail CI with exit code 1 if threshold met: 'quantum-vulnerable', 'critical', 'high', 'any'")
	cmd.Flags().StringVar(&exposure, "exposure", "internet", "Asset exposure factor: 'internet' (1.5), 'internal' (1.0), 'offline' (0.7)")
	cmd.Flags().StringVar(&dataLifetime, "data-lifetime", "medium", "Confidentiality lifetime factor: 'long' (>10y), 'medium' (1-10y), 'short' (<1y)")
	cmd.Flags().StringVar(&projectName, "project-name", "", "Project name for CBOM metadata")
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to .qcore-baseline.json to suppress accepted risks")
	cmd.Flags().StringVar(&signWithKey, "sign-with", "", "Ed25519 private key path to cryptographically sign the audit attestation")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Authority or CISO identity signing the audit attestation")
	cmd.Flags().StringVar(&bundleFile, "bundle", "", "Path to signed offline capability bundle (.json)")
	cmd.Flags().StringVar(&trustedKey, "trusted-key", "", "Base64 vendor public key to verify capability bundle")
	cmd.Flags().StringVar(&licenseFile, "license", "", "Path to signed offline license certificate (.lic/.json)")
	cmd.Flags().StringVar(&vendorKey, "vendor-key", "", "Base64 vendor public key to verify offline license")

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

func newKeygenCmd() *cobra.Command {
	var outKey, outPub string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate Ed25519 keypair for cryptographic audit signing",
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, pub, err := attestation.GenerateKeyPair()
			if err != nil {
				return err
			}
			if outKey == "" {
				outKey = "qcore.key"
			}
			if outPub == "" {
				outPub = "qcore.pub"
			}
			if err := os.WriteFile(outKey, []byte(priv), 0600); err != nil {
				return err
			}
			if err := os.WriteFile(outPub, []byte(pub), 0644); err != nil {
				return err
			}
			fmt.Printf("Generated signing keypair:\n  Private key: %s (mode 0600)\n  Public key:  %s\n", outKey, outPub)
			return nil
		},
	}
	cmd.Flags().StringVar(&outKey, "out-key", "qcore.key", "Output path for private signing key")
	cmd.Flags().StringVar(&outPub, "out-pub", "qcore.pub", "Output path for public verification key")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	var attPath, reportPath, cbomPath, pubKeyPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a cryptographically signed audit certificate and prove tamper resistance",
		RunE: func(cmd *cobra.Command, args []string) error {
			if attPath == "" {
				return fmt.Errorf("--attestation flag is required")
			}
			attData, err := os.ReadFile(attPath)
			if err != nil {
				return fmt.Errorf("failed reading attestation: %w", err)
			}
			att, err := attestation.FromJSON(attData)
			if err != nil {
				return fmt.Errorf("failed parsing attestation: %w", err)
			}

			var reportBytes, cbomBytes []byte
			if reportPath != "" {
				reportBytes, _ = os.ReadFile(reportPath)
			}
			if cbomPath != "" {
				cbomBytes, _ = os.ReadFile(cbomPath)
			}

			var expectedPub string
			if pubKeyPath != "" {
				pubRaw, err := os.ReadFile(pubKeyPath)
				if err != nil {
					return fmt.Errorf("failed reading public key: %w", err)
				}
				expectedPub = strings.TrimSpace(string(pubRaw))
			}

			valid, msg := attestation.VerifyAttestation(att, reportBytes, cbomBytes, expectedPub)
			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			fmt.Println("   VARDHAN Q-CORE :: CRYPTOGRAPHIC ATTESTATION VERIFICATION")
			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			fmt.Printf(" Attestation ID:    %s\n", att.ID)
			fmt.Printf(" Issuer:            %s\n", att.Issuer)
			fmt.Printf(" Timestamp:         %s\n", att.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf(" Target Directory:  %s\n", att.Target.Directory)
			fmt.Printf(" Quantum Risk KPI:  %d vulnerable usages | Max Score: %.1f\n",
				att.Summary.QuantumVulnerableCount, att.Summary.MaxRiskScore)
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			if valid {
				fmt.Printf(" STATUS: [VERIFIED AUTHENTIC] %s\n", msg)
			} else {
				fmt.Printf(" STATUS: [FAILED / TAMPERED]  %s\n", msg)
				os.Exit(1)
			}
			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			return nil
		},
	}
	cmd.Flags().StringVar(&attPath, "attestation", "", "Path to audit attestation JSON file")
	cmd.Flags().StringVar(&reportPath, "report", "", "Path to original report JSON file (to verify content digest)")
	cmd.Flags().StringVar(&cbomPath, "cbom", "", "Path to original CBOM JSON file (to verify CBOM digest)")
	cmd.Flags().StringVar(&pubKeyPath, "pubkey", "", "Path to trusted public key file (optional)")
	return cmd
}

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage accepted risk baselines and exemptions (PRD F-08)",
	}

	var approver, reason, outPath string
	var validityDays int

	initCmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Snapshot existing scan findings into an approved baseline register",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}
			absTarget, err := filepath.Abs(targetDir)
			if err != nil {
				return err
			}

			engine, err := rules.NewDefaultEngine()
			if err != nil {
				return err
			}
			sc := scanner.NewScanner(engine, Version)
			report, err := sc.ScanDirectory(absTarget)
			if err != nil {
				return err
			}

			if approver == "" {
				approver = "CISO / AppSec Lead"
			}
			if reason == "" {
				reason = "Approved legacy cryptography pending PQC migration plan"
			}
			if outPath == "" {
				outPath = ".qcore-baseline.json"
			}

			bl := baseline.CreateFromReport(report, approver, reason, validityDays)
			if err := bl.Save(outPath); err != nil {
				return fmt.Errorf("failed saving baseline: %w", err)
			}

			fmt.Printf("Initialized baseline at %s with %d approved exceptions.\n", outPath, len(bl.Exceptions))
			fmt.Printf("Approved By: %s | Reason: %s | Validity: %d days\n", approver, reason, validityDays)
			return nil
		},
	}
	initCmd.Flags().StringVar(&approver, "approved-by", "AppSec Lead", "Name or email of approving security officer")
	initCmd.Flags().StringVar(&reason, "reason", "Initial risk acceptance baseline", "Formal business reason for acceptance")
	initCmd.Flags().IntVar(&validityDays, "days", 365, "Validity duration in days before exception expires")
	initCmd.Flags().StringVarP(&outPath, "out", "o", ".qcore-baseline.json", "Output baseline file path")

	cmd.AddCommand(initCmd)
	return cmd
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

func newBenchmarkCmd() *cobra.Command {
	var (
		minPrecision float64
		minRecall    float64
		maxFPRate    float64
	)

	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Evaluate rule accuracy, precision, and recall against the ground-truth corpus",
		RunE: func(cmd *cobra.Command, args []string) error {
			engine, err := rules.NewDefaultEngine()
			if err != nil {
				return fmt.Errorf("failed to load rule engine: %w", err)
			}

			thresholds := benchmark.Thresholds{
				MinPrecision: minPrecision,
				MinRecall:    minRecall,
				MaxFPRate:    maxFPRate,
			}

			runner := benchmark.NewRunner(engine, thresholds)
			metrics := runner.Run(benchmark.SeededCorpus)

			fmt.Print(metrics.PrintReport())

			if !metrics.PassedGate {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().Float64Var(&minPrecision, "min-precision", 0.85, "Minimum required precision (0.0 to 1.0)")
	cmd.Flags().Float64Var(&minRecall, "min-recall", 0.85, "Minimum required recall (0.0 to 1.0)")
	cmd.Flags().Float64Var(&maxFPRate, "max-fp", 0.15, "Maximum allowed false-positive rate (0.0 to 1.0)")

	return cmd
}

func newLicenseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Manage and verify air-gapped offline enterprise licenses (PRD L-03)",
	}

	var customer, tier, keyPath, outPath string
	var validityDays, graceDays, maxRepos int
	var features []string

	genCmd := &cobra.Command{
		Use:   "generate",
		Short: "Issue a cryptographically signed offline license certificate (Vendor tool)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if customer == "" {
				return fmt.Errorf("--customer is required")
			}
			if keyPath == "" {
				return fmt.Errorf("--key is required (vendor master private key)")
			}
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("failed reading vendor key: %w", err)
			}
			privKeyStr := strings.TrimSpace(string(keyBytes))

			if len(features) == 0 {
				features = []string{"cbom", "sarif", "attestation", "offline_bundle", "airgap"}
			}

			lic, err := license.GenerateLicense(customer, tier, validityDays, graceDays, maxRepos, features, privKeyStr)
			if err != nil {
				return fmt.Errorf("failed generating license: %w", err)
			}

			if outPath == "" {
				outPath = "qcore.lic"
			}
			if err := lic.Save(outPath); err != nil {
				return fmt.Errorf("failed saving license: %w", err)
			}

			fmt.Printf("Issued offline license:\n  License ID:    %s\n  Customer:      %s\n  Tier:          %s\n  Valid Until:   %s (+%d days grace)\n  Saved To:      %s\n",
				lic.LicenseID, lic.CustomerName, lic.Tier, lic.ExpiresAt.Format("2006-01-02"), lic.GracePeriodDays, outPath)
			return nil
		},
	}
	genCmd.Flags().StringVar(&customer, "customer", "", "Customer / Financial Institution name")
	genCmd.Flags().StringVar(&tier, "tier", "ENTERPRISE_AIRGAP", "License tier (ENTERPRISE_AIRGAP, MIDMARKET_ANNUAL, TRIAL)")
	genCmd.Flags().IntVar(&validityDays, "days", 365, "Validity duration in days")
	genCmd.Flags().IntVar(&graceDays, "grace-days", 14, "Grace period duration in days after expiry")
	genCmd.Flags().IntVar(&maxRepos, "max-repos", 0, "Maximum repositories allowed (0 = unlimited)")
	genCmd.Flags().StringSliceVar(&features, "features", nil, "Licensed capabilities")
	genCmd.Flags().StringVar(&keyPath, "key", "", "Path to vendor Ed25519 private key")
	genCmd.Flags().StringVarP(&outPath, "out", "o", "qcore.lic", "Output license file path")

	var licPath, vendorKeyPath string
	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect and verify an offline license certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if licPath == "" {
				return fmt.Errorf("--license is required")
			}
			lic, err := license.Load(licPath)
			if err != nil {
				return err
			}

			var vendorKey string
			if vendorKeyPath != "" {
				kBytes, err := os.ReadFile(vendorKeyPath)
				if err != nil {
					return err
				}
				vendorKey = strings.TrimSpace(string(kBytes))
			}

			valid, inGrace, msg := lic.Verify(vendorKey)

			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			fmt.Println("   VARDHAN Q-CORE :: OFFLINE ENTERPRISE LICENSE CERTIFICATE")
			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			fmt.Printf(" License ID:     %s\n", lic.LicenseID)
			fmt.Printf(" Customer:       %s\n", lic.CustomerName)
			fmt.Printf(" License Tier:   %s\n", lic.Tier)
			fmt.Printf(" Issued At:      %s\n", lic.IssuedAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf(" Expires At:     %s (+%d days grace period)\n", lic.ExpiresAt.Format("2006-01-02"), lic.GracePeriodDays)
			fmt.Printf(" Authorized:     %s\n", strings.Join(lic.Features, ", "))
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			if valid {
				if inGrace {
					fmt.Printf(" STATUS: [GRACE PERIOD ACTIVE] %s\n", msg)
				} else {
					fmt.Printf(" STATUS: [ACTIVE & VALID] %s\n", msg)
				}
			} else {
				fmt.Printf(" STATUS: [BLOCKED / EXPIRED] %s\n", msg)
				os.Exit(1)
			}
			fmt.Println("══════════════════════════════════════════════════════════════════════════════")
			return nil
		},
	}
	inspectCmd.Flags().StringVarP(&licPath, "license", "l", "qcore.lic", "Path to offline license file")
	inspectCmd.Flags().StringVar(&vendorKeyPath, "vendor-key", "", "Path to vendor public key file (optional)")

	cmd.AddCommand(genCmd)
	cmd.AddCommand(inspectCmd)
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
			fmt.Println("  • Audit Signing:  Ed25519 Cryptographic Attestation Certificates")
		},
	}
}
