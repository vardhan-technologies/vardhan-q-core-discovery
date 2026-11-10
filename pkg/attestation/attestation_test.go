package attestation_test

import (
	"testing"
	"time"

	"github.com/vardhan/qcore/pkg/attestation"
	"github.com/vardhan/qcore/pkg/model"
)

func TestAttestationLifecycleAndTamperProof(t *testing.T) {
	// 1. Generate Keypair
	privKey, pubKey, err := attestation.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	report := &model.ScanReport{
		Metadata: model.ScanMetadata{
			ToolName:        "Vardhan Q-Core",
			ToolVersion:     "0.1.0",
			ScanTimestamp:   time.Now(),
			TargetDirectory: "/repo/core-banking",
			RulesLoaded:     42,
		},
		Summary: model.ScanSummary{
			TotalFindings:          5,
			QuantumVulnerableCount: 3,
			WeakClassicalCount:     2,
			MaxRiskScore:           78.4,
		},
	}

	rawReport := []byte(`{"scan":"valid-financial-repo","findings":5}`)
	rawCBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)

	// 2. Create Attestation
	att, err := attestation.CreateAttestation(report, rawReport, rawCBOM, "Bank Security Officer", privKey)
	if err != nil {
		t.Fatalf("CreateAttestation failed: %v", err)
	}

	// 3. Verify Valid Attestation
	valid, msg := attestation.VerifyAttestation(att, rawReport, rawCBOM, pubKey)
	if !valid {
		t.Fatalf("Expected valid attestation, but failed: %s", msg)
	}
	t.Logf("Success: %s", msg)

	// 4. Test Tampering with Report Content (Simulate an attacker altering findings)
	tamperedReport := []byte(`{"scan":"valid-financial-repo","findings":0}`) // attacker changed findings to 0
	validTamper, _ := attestation.VerifyAttestation(att, tamperedReport, rawCBOM, pubKey)
	if validTamper {
		t.Fatalf("Expected verification to FAIL on tampered report content, but it passed!")
	}
	t.Log("Verified: Attestation successfully blocked tampered report content.")

	// 5. Test Tampering with CBOM
	tamperedCBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","altered":true}`)
	validCBOMTamper, _ := attestation.VerifyAttestation(att, rawReport, tamperedCBOM, pubKey)
	if validCBOMTamper {
		t.Fatalf("Expected verification to FAIL on tampered CBOM, but it passed!")
	}
	t.Log("Verified: Attestation successfully blocked tampered CBOM content.")

	// 6. Test Tampering with Metadata inside the Attestation itself
	att.Summary.QuantumVulnerableCount = 0 // attacker tries to falsify the certificate summary
	validMetaTamper, _ := attestation.VerifyAttestation(att, rawReport, rawCBOM, pubKey)
	if validMetaTamper {
		t.Fatalf("Expected verification to FAIL on forged attestation metadata, but it passed!")
	}
	t.Log("Verified: Cryptographic signature blocked forged attestation metadata.")
}
