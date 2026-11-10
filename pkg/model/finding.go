package model

import (
	"time"
)

// ConfidenceLevel represents how certain we are about a finding.
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "HIGH"
	ConfidenceMedium ConfidenceLevel = "MEDIUM"
	ConfidenceLow    ConfidenceLevel = "LOW"
)

// Severity represents finding urgency.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Category groups the finding type.
type Category string

const (
	CategoryQuantumVulnerable Category = "quantum-vulnerable-public-key"
	CategoryWeakClassical      Category = "weak-classical-cryptography"
	CategoryQuantumReady       Category = "quantum-ready-pqc"
	CategoryVulnerableDep      Category = "vulnerable-dependency"
	CategoryConfigWeakness     Category = "cryptographic-configuration"
)

// PrimitiveType classifies the cryptographic primitive.
type PrimitiveType string

const (
	PrimitivePKE         PrimitiveType = "pke"          // Public Key Encryption
	PrimitiveKeyExchange PrimitiveType = "key-exchange" // Key Exchange / KEM
	PrimitiveSignature   PrimitiveType = "signature"    // Digital Signature
	PrimitiveBlockCipher PrimitiveType = "block-cipher" // Symmetric Block Cipher
	PrimitiveHash        PrimitiveType = "hash"         // Cryptographic Hash
	PrimitiveMAC         PrimitiveType = "mac"          // Message Authentication Code
	PrimitiveKDF         PrimitiveType = "kdf"          // Key Derivation Function
)

// Location specifies exact file and line coordinates.
type Location struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Snippet   string `json:"snippet,omitempty"`
}

// CryptoAsset represents a discovered cryptographic usage or item.
type CryptoAsset struct {
	ID                       string            `json:"id"`
	Name                     string            `json:"name"`                     // e.g. "RSA", "ECDSA-P256", "ML-KEM-768"
	Primitive                PrimitiveType     `json:"primitive"`                // e.g. "signature", "key-exchange"
	ParameterSetIdentifier   string            `json:"parameter_set,omitempty"`  // e.g. "2048", "P-256", "768"
	KeySize                  int               `json:"key_size,omitempty"`       // Key size in bits if known
	Mode                     string            `json:"mode,omitempty"`           // e.g. "ECB", "GCM", "CBC"
	Library                  string            `json:"library,omitempty"`        // e.g. "crypto/rsa", "bouncycastle", "cryptography"
	LibraryVersion           string            `json:"library_version,omitempty"`
	ProtocolContext          string            `json:"protocol_context,omitempty"` // e.g. "TLS", "SSH", "JWT"
	QuantumVulnerable        bool              `json:"quantum_vulnerable"`
	NISTQuantumSecurityLevel int               `json:"nist_quantum_security_level"` // 0=vulnerable, 1, 2, 3, 5 for PQC
	ClassicalSecurityLevel   int               `json:"classical_security_level"`   // e.g. 112, 128, 256
	Locations                []Location        `json:"locations"`
	Confidence               ConfidenceLevel   `json:"confidence"`
	Properties               map[string]string `json:"properties,omitempty"`
}

// Finding represents a single discovered issue or positive observation.
type Finding struct {
	ID                string          `json:"id"`
	RuleID            string          `json:"rule_id"`
	Title             string          `json:"title"`
	Category          Category        `json:"category"`
	Severity          Severity        `json:"severity"`
	Confidence        ConfidenceLevel `json:"confidence"`
	QuantumVulnerable bool            `json:"quantum_vulnerable"`
	Algorithm         string          `json:"algorithm"`
	KeySize           int             `json:"key_size,omitempty"`
	Location          Location        `json:"location"`
	Message           string          `json:"message"`
	Remediation       string          `json:"remediation"`
	References        []string        `json:"references"`
	RiskScore         float64         `json:"risk_score"`
	AssetRef          string          `json:"asset_ref,omitempty"`
}

// ScanMetadata captures environment and tool versions.
type ScanMetadata struct {
	ToolName        string    `json:"tool_name"`
	ToolVersion     string    `json:"tool_version"`
	ScanTimestamp   time.Time `json:"scan_timestamp"`
	TargetDirectory string    `json:"target_directory"`
	FilesScanned    int       `json:"files_scanned"`
	DurationMs      int64     `json:"duration_ms"`
	RulesLoaded     int       `json:"rules_loaded"`
}

// ScanSummary aggregates high-level metrics.
type ScanSummary struct {
	TotalFindings          int            `json:"total_findings"`
	QuantumVulnerableCount int            `json:"quantum_vulnerable_count"`
	WeakClassicalCount     int            `json:"weak_classical_count"`
	QuantumReadyCount      int            `json:"quantum_ready_count"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	AlgorithmMix           map[string]int `json:"algorithm_mix"`
	MaxRiskScore           float64        `json:"max_risk_score"`
	AverageRiskScore       float64        `json:"average_risk_score"`
}

// ScanReport represents the complete output of a scan.
type ScanReport struct {
	Metadata ScanMetadata  `json:"metadata"`
	Summary  ScanSummary   `json:"summary"`
	Assets   []CryptoAsset `json:"assets"`
	Findings []Finding     `json:"findings"`
}
