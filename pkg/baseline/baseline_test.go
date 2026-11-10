package baseline_test

import (
	"testing"
	"time"

	"github.com/vardhan/qcore/pkg/baseline"
	"github.com/vardhan/qcore/pkg/model"
)

func TestBaselineSuppressionAndExpiration(t *testing.T) {
	report := &model.ScanReport{
		Summary: model.ScanSummary{
			TotalFindings:          2,
			QuantumVulnerableCount: 2,
		},
		Findings: []model.Finding{
			{
				RuleID:            "go-rsa-keygen",
				Algorithm:         "RSA",
				Category:          model.CategoryQuantumVulnerable,
				QuantumVulnerable: true,
				Location: model.Location{
					FilePath:  "auth/rsa.go",
					StartLine: 12,
				},
			},
			{
				RuleID:            "go-ecdsa-keygen",
				Algorithm:         "ECDSA",
				Category:          model.CategoryQuantumVulnerable,
				QuantumVulnerable: true,
				Location: model.Location{
					FilePath:  "auth/ecdsa.go",
					StartLine: 45,
				},
			},
		},
	}

	// 1. Create Baseline with RSA accepted for 30 days, but ECDSA already expired
	b := baseline.NewBaseline()
	now := time.Now().UTC()

	fpRSA := baseline.ComputeFingerprint("auth/rsa.go", "go-rsa-keygen", "RSA")
	b.Exceptions[fpRSA] = baseline.BaselineException{
		Fingerprint: fpRSA,
		RuleID:      "go-rsa-keygen",
		FilePath:    "auth/rsa.go",
		Algorithm:   "RSA",
		Reason:      "Approved legacy gateway",
		ApprovedBy:  "appsec@bank.com",
		ApprovedAt:  now,
		ExpiresAt:   now.Add(30 * 24 * time.Hour), // 30 days active
	}

	fpECDSA := baseline.ComputeFingerprint("auth/ecdsa.go", "go-ecdsa-keygen", "ECDSA")
	b.Exceptions[fpECDSA] = baseline.BaselineException{
		Fingerprint: fpECDSA,
		RuleID:      "go-ecdsa-keygen",
		FilePath:    "auth/ecdsa.go",
		Algorithm:   "ECDSA",
		Reason:      "Temporary exception",
		ApprovedBy:  "appsec@bank.com",
		ApprovedAt:  now.Add(-60 * 24 * time.Hour),
		ExpiresAt:   now.Add(-1 * 24 * time.Hour), // Expired yesterday!
	}

	// 2. Apply Baseline
	res := b.Apply(report)

	if res.ActiveExceptions != 1 {
		t.Errorf("Expected 1 active exception, got %d", res.ActiveExceptions)
	}
	if res.ExpiredExceptions != 1 {
		t.Errorf("Expected 1 expired exception, got %d", res.ExpiredExceptions)
	}

	// Active quantum vulnerable count should have decreased from 2 to 1 (because RSA was accepted)
	if report.Summary.QuantumVulnerableCount != 1 {
		t.Errorf("Expected active QuantumVulnerableCount to be 1, got %d", report.Summary.QuantumVulnerableCount)
	}

	t.Log("Verified: Baseline successfully suppressed valid exception and flagged expired exception.")
}
