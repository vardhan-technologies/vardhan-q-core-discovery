package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vardhan/qcore/pkg/rules"
	"github.com/vardhan/qcore/pkg/scanner"
)

// CapabilityBundle represents a signed, offline-deliverable intelligence bundle.
type CapabilityBundle struct {
	BundleVersion string                      `json:"bundle_version"`
	CreatedAt     time.Time                   `json:"created_at"`
	Description   string                      `json:"description"`
	RulesYAML     []string                    `json:"rules_yaml"`
	Capabilities  []scanner.CryptoLibraryInfo `json:"capabilities"`
	Signature     string                      `json:"signature_base64"`
	PublicKey     string                      `json:"public_key_base64"`
}

// Package creates and cryptographically signs an offline capability bundle.
func Package(rulesYAML []string, caps []scanner.CryptoLibraryInfo, privKeyBase64, version, desc string) (*CapabilityBundle, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil || len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	b := &CapabilityBundle{
		BundleVersion: version,
		CreatedAt:     time.Now().UTC(),
		Description:   desc,
		RulesYAML:     rulesYAML,
		Capabilities:  caps,
		PublicKey:     base64.StdEncoding.EncodeToString(pubKey),
	}

	canonicalHash := b.computeDigest()
	sig := ed25519.Sign(privKey, canonicalHash)
	b.Signature = base64.StdEncoding.EncodeToString(sig)

	return b, nil
}

// computeDigest creates a deterministic payload digest over bundle contents.
func (b *CapabilityBundle) computeDigest() []byte {
	h := sha256.New()
	h.Write([]byte(b.BundleVersion))
	h.Write([]byte(b.CreatedAt.Format(time.RFC3339)))
	h.Write([]byte(b.Description))
	for _, r := range b.RulesYAML {
		h.Write([]byte(r))
	}
	for _, c := range b.Capabilities {
		h.Write([]byte(fmt.Sprintf("%s|%s|%s", c.Name, c.MinPQCVer, c.PQCStatus)))
	}
	return h.Sum(nil)
}

// Verify checks the cryptographic integrity and authenticity of the bundle.
func (b *CapabilityBundle) Verify(trustedPubKeyBase64 string) (bool, error) {
	pubKeyBase64 := b.PublicKey
	if trustedPubKeyBase64 != "" {
		if trustedPubKeyBase64 != b.PublicKey {
			return false, fmt.Errorf("bundle key does not match trusted vendor key")
		}
		pubKeyBase64 = trustedPubKeyBase64
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid ed25519 public key")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature")
	}

	canonicalHash := b.computeDigest()
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), canonicalHash, sigBytes) {
		return false, fmt.Errorf("tampered bundle signature verification failed")
	}

	return true, nil
}

// Install verifies and installs the bundle into the rule engine and capability DB.
func (b *CapabilityBundle) Install(engine *rules.Engine, trustedPubKeyBase64 string) error {
	valid, err := b.Verify(trustedPubKeyBase64)
	if !valid || err != nil {
		return fmt.Errorf("offline update rejected: %w", err)
	}

	// Install rules
	for i, ruleRaw := range b.RulesYAML {
		if err := engine.LoadYAMLBytes([]byte(ruleRaw)); err != nil {
			return fmt.Errorf("failed installing rule %d from bundle: %w", i+1, err)
		}
	}

	// Install capability mappings
	for _, c := range b.Capabilities {
		scanner.CapabilityDB[c.Name] = c
	}

	return nil
}

// SaveToFile exports bundle to disk.
func (b *CapabilityBundle) SaveToFile(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadFromFile reads bundle from disk.
func LoadFromFile(path string) (*CapabilityBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b CapabilityBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
