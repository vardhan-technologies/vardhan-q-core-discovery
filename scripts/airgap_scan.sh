#!/usr/bin/env bash
# ==============================================================================
# Vardhan Q-Core :: Automated Air-Gapped Scanner Runner (PRD L-02 & Section 10)
# ==============================================================================
set -euo pipefail

TARGET_PATH="${1:-./testdata/samples}"
OUTPUT_DIR="${2:-./output}"
PROJECT_NAME="${3:-airgap-financial-system}"

mkdir -p "${OUTPUT_DIR}"

echo "══════════════════════════════════════════════════════════════════════════════"
echo "   VARDHAN Q-CORE :: ZERO-EGRESS AIR-GAPPED DISCOVERY RUNNER"
echo "══════════════════════════════════════════════════════════════════════════════"
echo " Target Repository:  ${TARGET_PATH}"
echo " Output Destination: ${OUTPUT_DIR}"
echo " Network Mode:       ISOLATED (network_mode: none / zero outbound egress)"
echo "──────────────────────────────────────────────────────────────────────────────"

# Generate temporary audit key for attestation signing if not present
if [ ! -f "${OUTPUT_DIR}/auditor.key" ]; then
    echo "[1/4] Initializing auditor Ed25519 signing keypair..."
    ./bin/qcore keygen --out-key "${OUTPUT_DIR}/auditor.key" --out-pub "${OUTPUT_DIR}/auditor.pub" >/dev/null
fi

echo "[2/4] Executing discovery scan and generating CycloneDX 1.6 CBOM..."
./bin/qcore scan "${TARGET_PATH}" \
    -f cbom \
    -o "${OUTPUT_DIR}/cbom.json" \
    --project-name "${PROJECT_NAME}"

echo "[3/4] Generating OASIS SARIF 2.1.0 vulnerability report..."
./bin/qcore scan "${TARGET_PATH}" \
    -f sarif \
    -o "${OUTPUT_DIR}/results.sarif" \
    --project-name "${PROJECT_NAME}"

echo "[4/4] Generating cryptographically signed audit certificate (Ed25519)..."
./bin/qcore scan "${TARGET_PATH}" \
    -f json \
    -o "${OUTPUT_DIR}/report.json" \
    --sign-with "${OUTPUT_DIR}/auditor.key" \
    --issuer "Vardhan Air-Gap Certification Authority" \
    --project-name "${PROJECT_NAME}" >/dev/null

echo "──────────────────────────────────────────────────────────────────────────────"
echo " Verifying attestation tamper-resistance..."
./bin/qcore verify \
    --attestation "${OUTPUT_DIR}/report.attestation.json" \
    --report "${OUTPUT_DIR}/report.json" \
    --pubkey "${OUTPUT_DIR}/auditor.pub"

echo ""
echo " Air-gapped scan complete! Generated artifacts:"
echo "  • CycloneDX 1.6 CBOM:      ${OUTPUT_DIR}/cbom.json"
echo "  • GitHub SARIF Report:     ${OUTPUT_DIR}/results.sarif"
echo "  • Full JSON Audit Log:     ${OUTPUT_DIR}/report.json"
echo "  • Signed Attestation Cert: ${OUTPUT_DIR}/report.attestation.json"
echo "══════════════════════════════════════════════════════════════════════════════"
