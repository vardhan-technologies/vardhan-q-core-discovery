package benchmark_test

import (
	"testing"

	"github.com/vardhan/qcore/pkg/benchmark"
	"github.com/vardhan/qcore/pkg/rules"
)

func TestAccuracyAndReliabilityBenchmark(t *testing.T) {
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to initialize rule engine: %v", err)
	}

	thresholds := benchmark.DefaultThresholds()
	runner := benchmark.NewRunner(engine, thresholds)

	metrics := runner.Run(benchmark.SeededCorpus)

	t.Log("\n" + metrics.PrintReport())

	if !metrics.PassedGate {
		t.Fatalf("Release gate failed! Precision: %.2f%%, Recall: %.2f%%, FP Rate: %.2f%%",
			metrics.Precision*100, metrics.Recall*100, metrics.FalsePositiveRate*100)
	}

	if metrics.Precision < 0.85 {
		t.Errorf("Precision %.2f below target of 85%%", metrics.Precision*100)
	}

	if metrics.Recall < 0.85 {
		t.Errorf("Recall %.2f below target of 85%%", metrics.Recall*100)
	}

	if metrics.FalsePositiveRate > 0.15 {
		t.Errorf("False positive rate %.2f exceeds limit of 15%%", metrics.FalsePositiveRate*100)
	}
}
