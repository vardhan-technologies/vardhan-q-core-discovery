package rules_test

import (
	"testing"

	"github.com/vardhan/qcore/pkg/rules"
)

func TestBundledRulesFixtures(t *testing.T) {
	engine, err := rules.NewDefaultEngine()
	if err != nil {
		t.Fatalf("Failed to initialize default rule engine: %v", err)
	}

	if engine.Count() == 0 {
		t.Fatalf("Expected bundled rules to be loaded, but got 0")
	}

	result := engine.TestAllRules()
	if len(result.Failures) > 0 {
		t.Fatalf("Rule verification failed:\n%s", result.String())
	}

	t.Logf("Successfully verified all %d bundled detection rules with 100%% positive and negative fixtures.", engine.Count())
}
