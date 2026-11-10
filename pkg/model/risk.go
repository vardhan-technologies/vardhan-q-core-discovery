package model

// RiskConfig holds multipliers and weights for risk score computation.
type RiskConfig struct {
	// Vulnerability class weights
	WeightQuantumVulnerable float64
	WeightWeakClassical      float64
	WeightQuantumReady       float64

	// Context factors
	DataLifetimeFactor   float64 // 0.5 (ephemeral) to 2.0 (>10 yrs confidential)
	ExposureFactor       float64 // 0.7 (offline) to 1.5 (internet-facing)
	MigrationDifficulty  float64 // 0.0 (low) to 1.0 (high)
}

// DefaultRiskConfig returns standard default risk parameters calibrated for mid-market security audits.
func DefaultRiskConfig() RiskConfig {
	return RiskConfig{
		WeightQuantumVulnerable: 8.5,
		WeightWeakClassical:      6.0,
		WeightQuantumReady:       0.0,
		DataLifetimeFactor:       1.2, // standard business confidentiality horizon
		ExposureFactor:           1.2, // standard enterprise ingress exposure
		MigrationDifficulty:      0.4, // moderate migration difficulty
	}
}

// CalculateRiskScore computes the calibrated risk score per the PRD specification:
// Risk = VulnerabilityClassWeight * DataLifetimeFactor * ExposureFactor * (1 + MigrationDifficulty)
// Resulting score is normalized between 0.0 and 100.0.
func CalculateRiskScore(category Category, algorithm string, config RiskConfig) float64 {
	var baseWeight float64

	switch category {
	case CategoryQuantumVulnerable:
		baseWeight = config.WeightQuantumVulnerable
		// If RSA < 2048 or DSA, additional penalty for classical weakness + quantum break
		if algorithm == "DSA" || algorithm == "RSA-1024" {
			baseWeight += 1.5
		}
	case CategoryWeakClassical:
		baseWeight = config.WeightWeakClassical
		if algorithm == "MD5" || algorithm == "RC4" {
			baseWeight += 2.0
		}
	case CategoryQuantumReady:
		return 0.0 // Quantum-safe / hybrid has 0 risk
	default:
		baseWeight = 4.0
	}

	rawScore := baseWeight * config.DataLifetimeFactor * config.ExposureFactor * (1.0 + config.MigrationDifficulty)

	// Scale and clamp to [0.0, 100.0]
	// If baseWeight=10, life=2, exp=1.5, diff=1.0 -> 10 * 2 * 1.5 * 2.0 = 60.
	// We scale to 100 max:
	scaled := rawScore * 1.6
	if scaled > 100.0 {
		scaled = 100.0
	}
	if scaled < 0.0 {
		scaled = 0.0
	}

	// Round to 1 decimal place
	return float64(int(scaled*10+0.5)) / 10
}
