package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultVendorPublicKey is the built-in vendor public key for Vardhan Technologies.
// Customers receive signed offline licenses verified against this trusted authority.
var DefaultVendorPublicKey = "VardhanMasterVendorKeyBase64Placeholder"

// OfflineLicense represents an air-gapped signed license certificate (PRD L-03).
type OfflineLicense struct {
	LicenseID       string    `json:"license_id"`
	CustomerName    string    `json:"customer_name"`
	Tier            string    `json:"tier"` // e.g. "ENTERPRISE_AIRGAP", "MIDMARKET_ANNUAL", "TRIAL"
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	GracePeriodDays int       `json:"grace_period_days"` // e.g. 14 days
	MaxRepositories int       `json:"max_repositories"` // 0 = unlimited
	Features        []string  `json:"features"`
	Signature       string    `json:"signature_base64"`
	VendorPublicKey string    `json:"vendor_public_key_base64,omitempty"`
}

// GenerateLicense creates and signs an offline license certificate using the vendor master private key.
func GenerateLicense(customer, tier string, validityDays, graceDays, maxRepos int, features []string, vendorPrivKeyBase64 string) (*OfflineLicense, error) {
	privBytes, err := base64.StdEncoding.DecodeString(vendorPrivKeyBase64)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid vendor master private key: must be 64-byte base64 Ed25519 key")
	}
	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	now := time.Now().UTC()
	lic := &OfflineLicense{
		LicenseID:       fmt.Sprintf("LIC-%s-%d", strings.ToUpper(sanitize(customer[:min(len(customer), 6)])), now.Unix()),
		CustomerName:    customer,
		Tier:            tier,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Duration(validityDays) * 24 * time.Hour),
		GracePeriodDays: graceDays,
		MaxRepositories: maxRepos,
		Features:        features,
		VendorPublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}

	digest := lic.computeDigest()
	sig := ed25519.Sign(privKey, digest)
	lic.Signature = base64.StdEncoding.EncodeToString(sig)

	return lic, nil
}

// computeDigest builds the canonical binary payload digest to sign/verify.
func (l *OfflineLicense) computeDigest() []byte {
	h := sha256.New()
	h.Write([]byte(l.LicenseID))
	h.Write([]byte(l.CustomerName))
	h.Write([]byte(l.Tier))
	h.Write([]byte(l.IssuedAt.Format(time.RFC3339)))
	h.Write([]byte(l.ExpiresAt.Format(time.RFC3339)))
	h.Write([]byte(fmt.Sprintf("%d|%d", l.GracePeriodDays, l.MaxRepositories)))
	for _, f := range l.Features {
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// VerifyLicense validates the digital signature and temporal validity of the offline license.
func (l *OfflineLicense) Verify(trustedVendorPubKeyBase64 string) (valid bool, inGrace bool, message string) {
	pubKeyStr := l.VendorPublicKey
	if trustedVendorPubKeyBase64 != "" {
		if l.VendorPublicKey != "" && l.VendorPublicKey != trustedVendorPubKeyBase64 {
			return false, false, "license signature key does not match trusted vendor authority"
		}
		pubKeyStr = trustedVendorPubKeyBase64
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false, false, "invalid vendor public key format"
	}
	pubKey := ed25519.PublicKey(pubBytes)

	// Verify cryptographic signature
	sigBytes, err := base64.StdEncoding.DecodeString(l.Signature)
	if err != nil {
		return false, false, "invalid signature format in license"
	}

	digest := l.computeDigest()
	if !ed25519.Verify(pubKey, digest, sigBytes) {
		return false, false, "license cryptographic signature is invalid or license has been tampered with"
	}

	now := time.Now().UTC()

	// Check if active before expiration
	if now.Before(l.ExpiresAt) {
		daysRemaining := int(l.ExpiresAt.Sub(now).Hours() / 24)
		return true, false, fmt.Sprintf("License is valid and active (%d days remaining until %s)",
			daysRemaining, l.ExpiresAt.Format("2006-01-02"))
	}

	// Check grace period
	graceExpiry := l.ExpiresAt.Add(time.Duration(l.GracePeriodDays) * 24 * time.Hour)
	if now.Before(graceExpiry) {
		daysRemaining := int(graceExpiry.Sub(now).Hours() / 24)
		return true, true, fmt.Sprintf("WARNING: License expired on %s, currently running under GRACE PERIOD (%d days remaining). Please renew your offline license bundle.",
			l.ExpiresAt.Format("2006-01-02"), daysRemaining)
	}

	return false, false, fmt.Sprintf("License and grace period expired on %s. Operation blocked.",
		graceExpiry.Format("2006-01-02"))
}

// HasFeature returns true if the license authorizes a specific capability.
func (l *OfflineLicense) HasFeature(feature string) bool {
	for _, f := range l.Features {
		if strings.EqualFold(f, feature) || f == "*" {
			return true
		}
	}
	return false
}

// Load loads an offline license from a file path.
func Load(path string) (*OfflineLicense, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lic OfflineLicense
	if err := json.Unmarshal(data, &lic); err != nil {
		return nil, fmt.Errorf("failed to parse offline license JSON: %w", err)
	}
	return &lic, nil
}

// Save writes an offline license to a file path.
func (l *OfflineLicense) Save(path string) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
