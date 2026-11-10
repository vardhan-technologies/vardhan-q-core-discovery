package scanner

// PQCStatus defines the quantum readiness of a cryptographic library version.
type PQCStatus string

const (
	PQCStatusUnsupported PQCStatus = "UNSUPPORTED"
	PQCStatusPartial     PQCStatus = "PARTIAL_HYBRID"
	PQCStatusSupported   PQCStatus = "SUPPORTED"
)

// CryptoLibraryInfo represents an entry in the local capability database.
type CryptoLibraryInfo struct {
	Ecosystem   string    `json:"ecosystem"` // "maven", "npm", "pypi", "golang"
	Name        string    `json:"name"`
	MinPQCVer   string    `json:"min_pqc_version,omitempty"` // Version that introduced NIST PQC (ML-KEM / ML-DSA)
	Algorithms  []string  `json:"algorithms"`
	PQCStatus   PQCStatus `json:"pqc_status"`
	Description string    `json:"description"`
}

// CapabilityDB contains curated mappings of known crypto libraries.
var CapabilityDB = map[string]CryptoLibraryInfo{
	// Go Ecosystem
	"golang.org/x/crypto": {
		Ecosystem:   "golang",
		Name:        "golang.org/x/crypto",
		MinPQCVer:   "v0.31.0",
		Algorithms:  []string{"RSA", "ECDSA", "Ed25519", "ChaCha20Poly1305", "ML-KEM-768"},
		PQCStatus:   PQCStatusSupported,
		Description: "Go Extended Cryptography library (added ML-KEM in recent versions)",
	},
	"github.com/cloudflare/circl": {
		Ecosystem:   "golang",
		Name:        "github.com/cloudflare/circl",
		MinPQCVer:   "v1.3.0",
		Algorithms:  []string{"ML-KEM", "Kyber", "Dilithium", "SIDH", "SPHINCS+"},
		PQCStatus:   PQCStatusSupported,
		Description: "Cloudflare Interoperable Reusable Cryptographic Library (PQC native)",
	},
	"github.com/open-quantum-safe/liboqs-go": {
		Ecosystem:   "golang",
		Name:        "github.com/open-quantum-safe/liboqs-go",
		MinPQCVer:   "v0.1.0",
		Algorithms:  []string{"ML-KEM", "ML-DSA", "Falcon", "SLH-DSA"},
		PQCStatus:   PQCStatusSupported,
		Description: "Go bindings for Open Quantum Safe liboqs",
	},

	// Java (Maven / Gradle)
	"org.bouncycastle:bcprov-jdk18on": {
		Ecosystem:   "maven",
		Name:        "org.bouncycastle:bcprov-jdk18on",
		MinPQCVer:   "1.78",
		Algorithms:  []string{"RSA", "ECDSA", "ML-KEM", "ML-DSA", "SLH-DSA", "Falcon"},
		PQCStatus:   PQCStatusSupported,
		Description: "Bouncy Castle Provider with NIST FIPS 203/204/205 post-quantum support",
	},
	"org.bouncycastle:bcprov-jdk15on": {
		Ecosystem:   "maven",
		Name:        "org.bouncycastle:bcprov-jdk15on",
		MinPQCVer:   "",
		Algorithms:  []string{"RSA", "DSA", "ECDSA", "DH"},
		PQCStatus:   PQCStatusUnsupported,
		Description: "Legacy Bouncy Castle Provider (pre-PQC)",
	},
	"org.bouncycastle:bcpkix-jdk18on": {
		Ecosystem:   "maven",
		Name:        "org.bouncycastle:bcpkix-jdk18on",
		MinPQCVer:   "1.78",
		Algorithms:  []string{"X.509", "CMS", "PQC-Certs"},
		PQCStatus:   PQCStatusSupported,
		Description: "Bouncy Castle PKIX with PQC certificate extensions",
	},

	// Python (PyPI)
	"cryptography": {
		Ecosystem:   "pypi",
		Name:        "cryptography",
		MinPQCVer:   "44.0.0", // pyca/cryptography adding ML-KEM/X25519MLKEM768
		Algorithms:  []string{"RSA", "ECDSA", "Ed25519", "AES", "X25519MLKEM768"},
		PQCStatus:   PQCStatusPartial,
		Description: "Python Cryptographic Authority library",
	},
	"pycryptodome": {
		Ecosystem:   "pypi",
		Name:        "pycryptodome",
		MinPQCVer:   "",
		Algorithms:  []string{"RSA", "DSA", "ECC", "AES", "DES", "MD5"},
		PQCStatus:   PQCStatusUnsupported,
		Description: "Self-contained Python crypto library (classical only)",
	},
	"oqs": {
		Ecosystem:   "pypi",
		Name:        "oqs",
		MinPQCVer:   "0.8.0",
		Algorithms:  []string{"ML-KEM", "ML-DSA", "Falcon", "SLH-DSA"},
		PQCStatus:   PQCStatusSupported,
		Description: "Python bindings for Open Quantum Safe liboqs",
	},

	// JavaScript / TypeScript (npm)
	"crypto-js": {
		Ecosystem:   "npm",
		Name:        "crypto-js",
		MinPQCVer:   "",
		Algorithms:  []string{"MD5", "SHA-1", "AES", "RC4", "TripleDES"},
		PQCStatus:   PQCStatusUnsupported,
		Description: "Legacy JavaScript standard crypto algorithms (classical only)",
	},
	"node-forge": {
		Ecosystem:   "npm",
		Name:        "node-forge",
		MinPQCVer:   "",
		Algorithms:  []string{"RSA", "DES", "AES", "MD5", "SHA-1"},
		PQCStatus:   PQCStatusUnsupported,
		Description: "Native implementation of TLS and PKI in JavaScript (classical only)",
	},
	"tweetnacl": {
		Ecosystem:   "npm",
		Name:        "tweetnacl",
		MinPQCVer:   "",
		Algorithms:  []string{"Ed25519", "Curve25519", "XSalsa20Poly1305"},
		PQCStatus:   PQCStatusUnsupported,
		Description: "Port of TweetNaCl / NaCl cryptographic library (classical ECC only)",
	},
	"@openquantumsafe/liboqs-node": {
		Ecosystem:   "npm",
		Name:        "@openquantumsafe/liboqs-node",
		MinPQCVer:   "0.1.0",
		Algorithms:  []string{"ML-KEM", "ML-DSA", "Falcon"},
		PQCStatus:   PQCStatusSupported,
		Description: "Open Quantum Safe Node.js bindings",
	},
}
