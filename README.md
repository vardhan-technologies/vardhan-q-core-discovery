# Vardhan Q-Core

> **Post-Quantum Cryptographic Discovery & CBOM Platform**  
> *Release 0.1 MVP — Fast, defensible cryptographic inventory and migration prioritization for regulated mid-market organizations.*

---

## 1. Overview

**Vardhan Q-Core** is a cryptographic discovery and migration-planning engine designed to help regulated organizations (financial institutions, fintechs, healthcare, and critical infrastructure) discover where quantum-vulnerable cryptography is used, prioritize migration effort by risk, and export an audit-ready **Cryptographic Bill of Materials (CBOM)** formatted in **CycloneDX 1.6**.

### Core Capabilities
* **Multi-Language Source Scanning:** Detects cryptographic algorithm usage, key sizes, primitives, and modes across **Go**, **Python**, **Java**, and **JavaScript/TypeScript**.
* **Manifest & Lockfile Dependency Analysis:** Analyzes `pom.xml`, `build.gradle`, `requirements.txt`, `poetry.lock`, `go.mod`, `go.sum`, `package.json`, and `package-lock.json` against a curated Cryptographic Capability Database.
* **Standards-Compliant Exports:**
  * **CycloneDX 1.6 CBOM:** Schema-compliant Cryptographic Bill of Materials with deterministic ordering.
  * **OASIS SARIF 2.1.0:** Direct ingestion into GitHub Code Scanning and GitLab Security Dashboards.
* **Declarative YAML Rule Engine:** Extensible rules with mandatory positive (`must_match`) and negative (`must_not_match`) test fixtures to guarantee zero regressions.
* **Calibrated Risk Scoring:** Transparent risk formula factoring in vulnerability class, data lifetime, network exposure, and migration difficulty.

---

## 2. Quickstart

### Build the Static Binary
```bash
make build
# Binary created at ./bin/qcore
```

### Run All Unit Tests & Rule Fixtures
```bash
make test
```

### Scan a Codebase
```bash
# Terminal Executive Summary
./bin/qcore scan /path/to/codebase

# Generate CycloneDX 1.6 CBOM
./bin/qcore scan /path/to/codebase -f cbom -o cbom.json

# Generate SARIF 2.1.0 for GitHub Code Scanning
./bin/qcore scan /path/to/codebase -f sarif -o results.sarif
```

---

## 3. CLI Commands & Options

```text
Usage:
  qcore scan [path] [flags]
  qcore rules [command]
  qcore version

Flags:
  -f, --format string          Output format: table, cbom, sarif, json (default "table")
  -o, --output string          Path to write report output
      --fail-on string         CI policy break: 'quantum-vulnerable', 'critical', 'high', 'any'
      --exposure string        Asset exposure factor: 'internet' (1.5), 'internal' (1.0), 'offline' (0.7)
      --data-lifetime string   Confidentiality lifetime: 'long' (>10y), 'medium' (1-10y), 'short' (<1y)
      --rules-dir string       Directory containing additional custom YAML rules
      --project-name string    Project name for CBOM metadata
```

### CI / CD Policy Enforcement
Fail a pull request or CI pipeline if new quantum-vulnerable cryptography is introduced:
```bash
qcore scan . --fail-on=quantum-vulnerable
```

---

## 4. Calibrated Risk Model

Per Section 8 & 12 of the Vardhan Q-Core PRD:
$$\text{Risk Score} = \text{Vulnerability Class Weight} \times \text{Data Lifetime Factor} \times \text{Exposure Factor} \times (1 + \text{Migration Difficulty})$$

* **Vulnerability Class:**
  * Quantum-Vulnerable Public Key (RSA, DSA, ECDSA, ECDH): High base weight (8.5 – 10.0)
  * Weak Classical Cryptography (MD5, SHA-1, 3DES, RC4, ECB): Medium base weight (6.0 – 8.0)
  * Quantum-Ready / Hybrid (ML-KEM, ML-DSA, X25519MLKEM768): **0.0 Risk** (Positive compliant finding)
* **Data Lifetime:** Long-lived (>10 years) data carries elevated Harvest-Now-Decrypt-Later (HNDL) risk.
* **Exposure:** Public internet-facing ingress surfaces score higher than internal services.

---

## 5. Declarative Rule Grammar

Rules are structured YAML documents stored in `rules/` (and compiled into the static binary). Every rule must contain positive and negative fixtures:

```yaml
id: go-rsa-keygen
language: go
regex: 'rsa\.GenerateKey\s*\('
finding:
  category: quantum-vulnerable-public-key
  algorithm: RSA
  primitive: signature
  quantum_vulnerable: true
  severity: HIGH
  message: >
    RSA key generation detected. RSA is vulnerable to Shor's algorithm at any key size.
    Plan migration to a hybrid or PQC digital signature (ML-DSA / FIPS 204).
  remediation: Migrate to ML-DSA (FIPS 204) for digital signatures or ML-KEM (FIPS 203) for key establishment.
  references:
    - NIST FIPS 203, FIPS 204
    - CNSA 2.0 Timeline
tests:
  must_match:
    - "key, err := rsa.GenerateKey(rand.Reader, 2048)"
  must_not_match:
    - "key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)"
    - "kemKey, err := mlkem.GenerateKey768()"
```

Verify the entire rule corpus anytime:
```bash
qcore rules test
```

---

## 6. Architecture & Directory Structure

```
vardhan-q-core/
├── cmd/
│   └── qcore/           # CLI main entrypoint (Cobra commands & flags)
├── pkg/
│   ├── model/           # Finding, CryptoAsset, RiskScore, and Report models
│   ├── rules/           # Declarative Rule Engine & Test Runner
│   │   └── bundled/     # Embedded YAML rule packs (embedded via //go:embed)
│   ├── scanner/         # Multi-language walker, AST regex matchers, dependency parser
│   ├── cbom/            # CycloneDX 1.6 Cryptographic Bill of Materials serializer
│   ├── sarif/           # OASIS SARIF 2.1.0 generator for GitHub Code Scanning
│   └── reporter/        # Terminal executive summary & ASCII reporting
├── rules/               # Source YAML rules (RSA, ECDSA/ECDH, DSA/DH, Classical, PQC)
├── testdata/samples/    # Real code fixtures (Go, Java, Python, JS + lockfiles)
├── .github/workflows/   # CI pipeline for automated testing and SARIF upload
└── Makefile             # Developer automation targets
```

---

## 7. Standards Compliance & References

* **CycloneDX 1.6:** Cryptographic Bill of Materials (CBOM) specification
* **OASIS SARIF 2.1.0:** Static Analysis Results Interchange Format
* **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
* **NIST FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
* **NIST FIPS 205:** Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)
* **NSA CNSA 2.0:** Commercial National Security Algorithm Suite 2.0
