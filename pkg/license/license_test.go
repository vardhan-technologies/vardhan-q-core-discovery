package license_test

import (
	"testing"

	"github.com/vardhan/qcore/pkg/attestation"
	"github.com/vardhan/qcore/pkg/license"
)

func TestOfflineLicenseLifecycleAndGracePeriod(t *testing.T) {
	// 1. Generate Vendor Keypair
	privKey, pubKey, err := attestation.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate vendor key: %v", err)
	}

	features := []string{"cbom", "sarif", "attestation", "airgap"}

	// 2. Test Active License (30 days validity)
	lic, err := license.GenerateLicense("Barclays Capital", "ENTERPRISE_AIRGAP", 30, 14, 50, features, privKey)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	valid, inGrace, msg := lic.Verify(pubKey)
	if !valid || inGrace {
		t.Fatalf("Expected active license to be valid without grace, got valid=%v inGrace=%v: %s", valid, inGrace, msg)
	}
	t.Logf("Success: %s", msg)

	if !lic.HasFeature("cbom") || !lic.HasFeature("attestation") {
		t.Errorf("Expected authorized features to be present")
	}

	// 3. Test Grace Period (Expired 2 days ago, 14 days grace period)
	licGrace, err := license.GenerateLicense("Revolut", "MIDMARKET_ANNUAL", -2, 14, 20, features, privKey)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	validG, inGraceG, msgG := licGrace.Verify(pubKey)
	if !validG || !inGraceG {
		t.Fatalf("Expected license to be valid under GRACE PERIOD, got valid=%v inGrace=%v: %s", validG, inGraceG, msgG)
	}
	t.Logf("Verified Grace Period: %s", msgG)

	// 4. Test Fully Expired (Expired 30 days ago, 14 days grace period -> completely expired)
	licExpired, err := license.GenerateLicense("Stale Bank", "TRIAL", -30, 14, 5, features, privKey)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	validE, _, msgE := licExpired.Verify(pubKey)
	if validE {
		t.Fatalf("Expected license to be EXPIRED and blocked, but it was valid: %s", msgE)
	}
	t.Logf("Verified Expiration: %s", msgE)

	// 5. Test Tampered License (Attacker alters customer or tier)
	lic.Tier = "ENTERPRISE_UNLIMITED"
	validT, _, msgT := lic.Verify(pubKey)
	if validT {
		t.Fatalf("Expected tampered license to FAIL cryptographic verification, but it passed!")
	}
	t.Logf("Verified Tamper Resistance: %s", msgT)
}
