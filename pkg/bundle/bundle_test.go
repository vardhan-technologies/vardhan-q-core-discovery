package bundle_test

import (
	"testing"

	"github.com/vardhan/qcore/pkg/attestation"
	"github.com/vardhan/qcore/pkg/bundle"
	"github.com/vardhan/qcore/pkg/rules"
	"github.com/vardhan/qcore/pkg/scanner"
)

func TestSignedCapabilityBundleLifecycle(t *testing.T) {
	// 1. Generate Vendor Keypair
	privKey, pubKey, err := attestation.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate vendor key: %v", err)
	}

	newRuleYAML := `
id: custom-pqc-slhdsa
language: go
regex: 'slhdsa\.GenerateKey\s*\('
finding:
  category: quantum-ready-pqc
  algorithm: SLH-DSA
  quantum_vulnerable: false
  severity: INFO
  message: NIST FIPS 205 Stateless Hash-Based Digital Signature in use.
`
	newCaps := []scanner.CryptoLibraryInfo{
		{
			Ecosystem:   "golang",
			Name:        "github.com/symbolic-pqc/slhdsa",
			MinPQCVer:   "v1.0.0",
			Algorithms:  []string{"SLH-DSA"},
			PQCStatus:   scanner.PQCStatusSupported,
			Description: "Stateless Hash-Based Signatures (FIPS 205)",
		},
	}

	// 2. Package and Sign Bundle
	b, err := bundle.Package([]string{newRuleYAML}, newCaps, privKey, "2026.11.1", "NIST FIPS 205 Update")
	if err != nil {
		t.Fatalf("Failed to package bundle: %v", err)
	}

	// 3. Verify Authenticity
	valid, err := b.Verify(pubKey)
	if !valid || err != nil {
		t.Fatalf("Bundle verification failed: %v", err)
	}
	t.Log("Verified: Signed bundle passes cryptographic signature verification.")

	// 4. Install into Engine
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to load engine: %v", err)
	}
	initialRuleCount := engine.Count()

	err = b.Install(engine, pubKey)
	if err != nil {
		t.Fatalf("Failed to install bundle: %v", err)
	}

	if engine.Count() != initialRuleCount+1 {
		t.Errorf("Expected engine rule count to increment by 1, got %d", engine.Count())
	}

	// Check capability DB was updated
	if _, exists := scanner.CapabilityDB["github.com/symbolic-pqc/slhdsa"]; !exists {
		t.Errorf("Expected new library in CapabilityDB, but not found")
	}
	t.Logf("Success: Installed signed offline update. Rule count expanded to %d.", engine.Count())

	// 5. Test Tampered Bundle (Attacker tries to inject rogue rule)
	b.RulesYAML[0] = b.RulesYAML[0] + "\n# altered rule"
	err = b.Install(engine, pubKey)
	if err == nil {
		t.Fatalf("Expected installation of tampered bundle to FAIL, but it succeeded!")
	}
	t.Log("Verified: Cryptographic signature successfully blocked installation of tampered bundle.")
}
