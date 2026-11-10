package benchmark

import (
	"fmt"
	"strings"

	"github.com/vardhan/qcore/pkg/rules"
)

// ExpectedFinding represents an expected detection in ground truth.
type ExpectedFinding struct {
	Algorithm string
	Category  string
}

// BenchmarkCase represents a ground-truth test case.
type BenchmarkCase struct {
	ID                  string
	Language            string
	CodeSnippet         string
	ExpectedMatches     []ExpectedFinding
	NegativeAssertions  []string // Algorithms that MUST NOT fire on this snippet
}

// Metrics tracks classification precision, recall, and error rates.
type Metrics struct {
	TotalCases        int
	TruePositives     int
	FalsePositives    int
	FalseNegatives    int
	TrueNegatives     int
	Precision         float64
	Recall            float64
	FalsePositiveRate float64
	F1Score           float64
	PassedGate        bool
	Failures          []string
}

// Thresholds defines the release gate acceptance criteria.
type Thresholds struct {
	MinPrecision float64 // e.g. 0.85 (85%)
	MinRecall    float64 // e.g. 0.85 (85%)
	MaxFPRate    float64 // e.g. 0.15 (15%)
}

// DefaultThresholds returns the Phase 1 MVP release gate thresholds from the PRD.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MinPrecision: 0.85, // >= 85%
		MinRecall:    0.85, // >= 85%
		MaxFPRate:    0.15, // <= 15%
	}
}

// Runner executes benchmark evaluation against ground truth.
type Runner struct {
	engine     *rules.Engine
	thresholds Thresholds
}

// NewRunner initializes a benchmark runner.
func NewRunner(engine *rules.Engine, thresholds Thresholds) *Runner {
	return &Runner{
		engine:     engine,
		thresholds: thresholds,
	}
}

// Run executes the seeded benchmark suite and returns metrics.
func (r *Runner) Run(corpus []BenchmarkCase) Metrics {
	m := Metrics{
		TotalCases: len(corpus),
	}

	for _, tc := range corpus {
		applicableRules := r.engine.RulesForLanguage(tc.Language)
		detectedAlgos := make(map[string]bool)

		for _, rule := range applicableRules {
			if rule.Matches(tc.CodeSnippet) {
				detectedAlgos[rule.Finding.Algorithm] = true
			}
		}

		// Evaluate Expected Matches (True Positives vs False Negatives)
		for _, exp := range tc.ExpectedMatches {
			if detectedAlgos[exp.Algorithm] {
				m.TruePositives++
			} else {
				m.FalseNegatives++
				m.Failures = append(m.Failures,
					fmt.Sprintf("[FN] Case %s: Expected %s but not detected", tc.ID, exp.Algorithm))
			}
		}

		// Evaluate Negative Assertions (False Positives vs True Negatives)
		for _, neg := range tc.NegativeAssertions {
			if detectedAlgos[neg] {
				m.FalsePositives++
				m.Failures = append(m.Failures,
					fmt.Sprintf("[FP] Case %s: False positive detected for %s", tc.ID, neg))
			} else {
				m.TrueNegatives++
			}
		}

		// If case is purely negative with no expected matches and zero detections
		if len(tc.ExpectedMatches) == 0 && len(detectedAlgos) == 0 {
			m.TrueNegatives++
		}
	}

	// Calculate statistical metrics
	if (m.TruePositives + m.FalsePositives) > 0 {
		m.Precision = float64(m.TruePositives) / float64(m.TruePositives+m.FalsePositives)
	} else {
		m.Precision = 1.0
	}

	if (m.TruePositives + m.FalseNegatives) > 0 {
		m.Recall = float64(m.TruePositives) / float64(m.TruePositives+m.FalseNegatives)
	} else {
		m.Recall = 1.0
	}

	if (m.FalsePositives + m.TrueNegatives) > 0 {
		m.FalsePositiveRate = float64(m.FalsePositives) / float64(m.FalsePositives+m.TrueNegatives)
	} else {
		m.FalsePositiveRate = 0.0
	}

	if (m.Precision + m.Recall) > 0 {
		m.F1Score = 2 * (m.Precision * m.Recall) / (m.Precision + m.Recall)
	}

	// Release Gate check
	m.PassedGate = m.Precision >= r.thresholds.MinPrecision &&
		m.Recall >= r.thresholds.MinRecall &&
		m.FalsePositiveRate <= r.thresholds.MaxFPRate

	return m
}

// PrintReport outputs a human-readable benchmark evaluation summary.
func (m Metrics) PrintReport() string {
	var sb strings.Builder
	sb.WriteString("══════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("   VARDHAN Q-CORE :: ACCURACY & RELIABILITY BENCHMARK REPORT\n")
	sb.WriteString("══════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf(" Benchmark Corpus:      %d Seeded Cases\n", m.TotalCases))
	sb.WriteString(fmt.Sprintf(" True Positives (TP):   %d\n", m.TruePositives))
	sb.WriteString(fmt.Sprintf(" True Negatives (TN):   %d\n", m.TrueNegatives))
	sb.WriteString(fmt.Sprintf(" False Positives (FP):  %d\n", m.FalsePositives))
	sb.WriteString(fmt.Sprintf(" False Negatives (FN):  %d\n", m.FalseNegatives))
	sb.WriteString("──────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf(" Precision:             %.2f%%  (Target: >= 85.00%%)\n", m.Precision*100))
	sb.WriteString(fmt.Sprintf(" Recall:                %.2f%%  (Target: >= 85.00%%)\n", m.Recall*100))
	sb.WriteString(fmt.Sprintf(" False Positive Rate:   %.2f%%  (Target: <= 15.00%%)\n", m.FalsePositiveRate*100))
	sb.WriteString(fmt.Sprintf(" F1 Score:              %.4f\n", m.F1Score))
	sb.WriteString("──────────────────────────────────────────────────────────────────────────────\n")

	if m.PassedGate {
		sb.WriteString(" RELEASE GATE STATUS:   [PASSED] All accuracy & reliability criteria met.\n")
	} else {
		sb.WriteString(" RELEASE GATE STATUS:   [FAILED] Precision/Recall/FP criteria violated!\n")
	}

	if len(m.Failures) > 0 {
		sb.WriteString("──────────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(" DISCREPANCIES / FAILURES:\n")
		for _, f := range m.Failures {
			sb.WriteString(fmt.Sprintf("  • %s\n", f))
		}
	}
	sb.WriteString("══════════════════════════════════════════════════════════════════════════════\n")
	return sb.String()
}
