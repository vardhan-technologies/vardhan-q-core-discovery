package cbom_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/vardhan/qcore/pkg/cbom"
	"github.com/vardhan/qcore/pkg/rules"
	"github.com/vardhan/qcore/pkg/scanner"
)

func TestCBOMDeterministicOrdering(t *testing.T) {
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to init engine: %v", err)
	}

	sc := scanner.NewScanner(engine, "0.1.0")
	testdataDir, err := filepath.Abs("../../testdata/samples")
	if err != nil {
		t.Fatalf("Failed to find testdata: %v", err)
	}

	// First scan
	report1, err := sc.ScanDirectory(testdataDir)
	if err != nil {
		t.Fatalf("Scan 1 failed: %v", err)
	}

	bom1, err := cbom.GenerateCBOM(report1, "deterministic-test")
	if err != nil {
		t.Fatalf("CBOM 1 generation failed: %v", err)
	}

	json1, err := cbom.ToJSON(bom1)
	if err != nil {
		t.Fatalf("CBOM 1 serialization failed: %v", err)
	}

	// Second scan (same timestamp simulation)
	report2, err := sc.ScanDirectory(testdataDir)
	if err != nil {
		t.Fatalf("Scan 2 failed: %v", err)
	}
	// Pin timestamp to check component serialization stability
	report2.Metadata.ScanTimestamp = report1.Metadata.ScanTimestamp

	bom2, err := cbom.GenerateCBOM(report2, "deterministic-test")
	if err != nil {
		t.Fatalf("CBOM 2 generation failed: %v", err)
	}

	json2, err := cbom.ToJSON(bom2)
	if err != nil {
		t.Fatalf("CBOM 2 serialization failed: %v", err)
	}

	// Verify exact byte-for-byte deterministic output
	if !bytes.Equal(json1, json2) {
		t.Fatalf("CBOM output is non-deterministic! Two consecutive scans on identical code produced different JSON outputs.")
	}

	t.Log("Verified: CycloneDX 1.6 CBOM produces byte-for-byte deterministic output.")
}

func TestCBOMSchemaCompliance(t *testing.T) {
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to init engine: %v", err)
	}

	sc := scanner.NewScanner(engine, "0.1.0")
	testdataDir, _ := filepath.Abs("../../testdata/samples")
	report, err := sc.ScanDirectory(testdataDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	bom, err := cbom.GenerateCBOM(report, "schema-check")
	if err != nil {
		t.Fatalf("Failed to generate CBOM: %v", err)
	}

	if bom.SpecVersion != "1.6" {
		t.Errorf("Expected CycloneDX specVersion 1.6, got %s", bom.SpecVersion)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat CycloneDX, got %s", bom.BOMFormat)
	}

	for _, comp := range bom.Components {
		if comp.Type != "cryptographic-asset" {
			t.Errorf("Component %s has type '%s', expected 'cryptographic-asset'", comp.Name, comp.Type)
		}
		if comp.CryptoProperties == nil {
			t.Errorf("Component %s is missing required cryptoProperties", comp.Name)
		}
		if comp.CryptoProperties.AssetType == "" {
			t.Errorf("Component %s has empty assetType", comp.Name)
		}
	}

	t.Logf("Verified: All %d CBOM components comply with CycloneDX 1.6 cryptographic-asset schema.", len(bom.Components))
}
