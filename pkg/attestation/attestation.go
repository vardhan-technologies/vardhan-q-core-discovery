package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vardhan/qcore/pkg/model"
)

// AuditAttestation represents a tamper-evident, cryptographically signed audit certificate.
type AuditAttestation struct {
	SpecVersion string           `json:"spec_version"` // "1.0"
	ID          string           `json:"id"`
	Timestamp   time.Time        `json:"timestamp"`
	Issuer      string           `json:"issuer"`
	Target      TargetMetadata   `json:"target"`
	Summary     AttestSummary    `json:"summary"`
	Digests     ArtifactDigests  `json:"digests"`
	Signature   string           `json:"signature_base64"`
	PublicKey   string           `json:"public_key_base64"`
}

type TargetMetadata struct {
	Directory   string `json:"directory"`
	ToolVersion string `json:"tool_version"`
	RulesLoaded int    `json:"rules_loaded"`
}

type AttestSummary struct {
	TotalFindings          int     `json:"total_findings"`
	QuantumVulnerableCount int     `json:"quantum_vulnerable_count"`
	WeakClassicalCount     int     `json:"weak_classical_count"`
	MaxRiskScore           float64 `json:"max_risk_score"`
}

type ArtifactDigests struct {
	ReportSHA256 string `json:"report_sha256"`
	CBOMSHA256   string `json:"cbom_sha256,omitempty"`
}

// GenerateKeyPair generates a new Ed25519 keypair for signing audit attestations.
func GenerateKeyPair() (privKeyBase64, pubKeyBase64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// CreateAttestation creates and cryptographically signs an audit attestation for a scan report.
func CreateAttestation(report *model.ScanReport, reportBytes []byte, cbomBytes []byte, issuer string, privKeyBase64 string) (*AuditAttestation, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil || len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key (must be 64 bytes base64)")
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	if issuer == "" {
		issuer = "Vardhan Technologies Audit Authority"
	}

	reportDigest := sha256.Sum256(reportBytes)
	digests := ArtifactDigests{
		ReportSHA256: hex.EncodeToString(reportDigest[:]),
	}
	if len(cbomBytes) > 0 {
		cbomDigest := sha256.Sum256(cbomBytes)
		digests.CBOMSHA256 = hex.EncodeToString(cbomDigest[:])
	}

	att := &AuditAttestation{
		SpecVersion: "1.0",
		ID:          fmt.Sprintf("qatt-%x", reportDigest[:8]),
		Timestamp:   time.Now().UTC(),
		Issuer:      issuer,
		Target: TargetMetadata{
			Directory:   report.Metadata.TargetDirectory,
			ToolVersion: report.Metadata.ToolVersion,
			RulesLoaded: report.Metadata.RulesLoaded,
		},
		Summary: AttestSummary{
			TotalFindings:          report.Summary.TotalFindings,
			QuantumVulnerableCount: report.Summary.QuantumVulnerableCount,
			WeakClassicalCount:     report.Summary.WeakClassicalCount,
			MaxRiskScore:           report.Summary.MaxRiskScore,
		},
		Digests:   digests,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}

	// Canonical payload to sign: ID + Timestamp + ReportSHA256 + CBOMSHA256 + Issuer
	canonicalToSign := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%.1f",
		att.ID,
		att.Timestamp.Format(time.RFC3339),
		att.Digests.ReportSHA256,
		att.Digests.CBOMSHA256,
		att.Issuer,
		att.Summary.QuantumVulnerableCount,
		att.Summary.MaxRiskScore,
	)

	sig := ed25519.Sign(privKey, []byte(canonicalToSign))
	att.Signature = base64.StdEncoding.EncodeToString(sig)

	return att, nil
}

// VerifyAttestation validates that an attestation's signature matches the report/CBOM and public key.
func VerifyAttestation(att *AuditAttestation, reportBytes []byte, cbomBytes []byte, expectedPubKeyBase64 string) (bool, string) {
	pubKeyBase64 := att.PublicKey
	if expectedPubKeyBase64 != "" {
		if expectedPubKeyBase64 != att.PublicKey {
			return false, fmt.Sprintf("attestation public key (%s) does not match trusted key (%s)",
				att.PublicKey, expectedPubKeyBase64)
		}
		pubKeyBase64 = expectedPubKeyBase64
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, "invalid ed25519 public key in attestation"
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Verify report digest
	if len(reportBytes) > 0 {
		reportDigest := sha256.Sum256(reportBytes)
		calculatedHex := hex.EncodeToString(reportDigest[:])
		if calculatedHex != att.Digests.ReportSHA256 {
			return false, fmt.Sprintf("report content tampering detected! Expected digest %s, got %s",
				att.Digests.ReportSHA256, calculatedHex)
		}
	}

	// Verify CBOM digest if present
	if len(cbomBytes) > 0 && att.Digests.CBOMSHA256 != "" {
		cbomDigest := sha256.Sum256(cbomBytes)
		calculatedHex := hex.EncodeToString(cbomDigest[:])
		if calculatedHex != att.Digests.CBOMSHA256 {
			return false, fmt.Sprintf("CBOM content tampering detected! Expected digest %s, got %s",
				att.Digests.CBOMSHA256, calculatedHex)
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(att.Signature)
	if err != nil {
		return false, "invalid base64 signature in attestation"
	}

	canonicalToSign := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%.1f",
		att.ID,
		att.Timestamp.Format(time.RFC3339),
		att.Digests.ReportSHA256,
		att.Digests.CBOMSHA256,
		att.Issuer,
		att.Summary.QuantumVulnerableCount,
		att.Summary.MaxRiskScore,
	)

	if !ed25519.Verify(pubKey, []byte(canonicalToSign), sigBytes) {
		return false, "cryptographic signature verification failed! Attestation header or metadata has been altered."
	}

	return true, "Attestation signature is cryptographically valid and authentic."
}

// ToJSON serializes the attestation.
func ToJSON(att *AuditAttestation) ([]byte, error) {
	return json.MarshalIndent(att, "", "  ")
}

// FromJSON deserializes an attestation.
func FromJSON(data []byte) (*AuditAttestation, error) {
	var att AuditAttestation
	if err := json.Unmarshal(data, &att); err != nil {
		return nil, err
	}
	return &att, nil
}
