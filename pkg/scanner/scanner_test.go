package scanner_test

import (
	"path/filepath"
	"testing"

	"github.com/vardhan/qcore/pkg/cbom"
	"github.com/vardhan/qcore/pkg/model"
	"github.com/vardhan/qcore/pkg/rules"
	"github.com/vardhan/qcore/pkg/sarif"
	"github.com/vardhan/qcore/pkg/scanner"
)

func TestEndToEndScan(t *testing.T) {
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to initialize rule engine: %v", err)
	}

	sc := scanner.NewScanner(engine, "0.1.0")
	testdataDir, err := filepath.Abs("../../testdata/samples")
	if err != nil {
		t.Fatalf("Failed to resolve testdata path: %v", err)
	}

	report, err := sc.ScanDirectory(testdataDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Verify Scan Results
	if report.Metadata.FilesScanned == 0 {
		t.Errorf("Expected files to be scanned, got 0")
	}

	if report.Summary.QuantumVulnerableCount == 0 {
		t.Errorf("Expected quantum vulnerable findings in test corpus, got 0")
	}

	if report.Summary.WeakClassicalCount == 0 {
		t.Errorf("Expected weak classical crypto findings in test corpus, got 0")
	}

	if report.Summary.QuantumReadyCount == 0 {
		t.Errorf("Expected quantum ready findings in test corpus, got 0")
	}

	// Verify CycloneDX 1.6 CBOM Generation
	bom, err := cbom.GenerateCBOM(report, "test-fintech-service")
	if err != nil {
		t.Fatalf("Failed to generate CBOM: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Errorf("Invalid CBOM spec: %s %s", bom.BOMFormat, bom.SpecVersion)
	}

	if len(bom.Components) == 0 {
		t.Errorf("Expected CBOM components, got 0")
	}

	// Test SARIF Generation
	sarifDoc, err := sarif.GenerateSARIF(report)
	if err != nil {
		t.Fatalf("Failed to generate SARIF: %v", err)
	}

	if sarifDoc.Version != "2.1.0" {
		t.Errorf("Invalid SARIF version: %s", sarifDoc.Version)
	}

	if len(sarifDoc.Runs[0].Results) != len(report.Findings) {
		t.Errorf("SARIF results count (%d) mismatch with findings count (%d)",
			len(sarifDoc.Runs[0].Results), len(report.Findings))
	}
}

func TestRiskScoreCalculation(t *testing.T) {
	cfg := model.DefaultRiskConfig()

	// Quantum vulnerable with long lifetime and internet exposure
	cfg.DataLifetimeFactor = 1.8
	cfg.ExposureFactor = 1.5
	cfg.MigrationDifficulty = 0.5

	scoreVulnerable := model.CalculateRiskScore(model.CategoryQuantumVulnerable, "RSA", cfg)
	if scoreVulnerable <= 0.0 || scoreVulnerable > 100.0 {
		t.Errorf("Expected risk score in range (0, 100], got %f", scoreVulnerable)
	}

	// Quantum ready should always be 0.0 risk
	scorePQC := model.CalculateRiskScore(model.CategoryQuantumReady, "ML-KEM-768", cfg)
	if scorePQC != 0.0 {
		t.Errorf("Expected PQC risk score 0.0, got %f", scorePQC)
	}
}
