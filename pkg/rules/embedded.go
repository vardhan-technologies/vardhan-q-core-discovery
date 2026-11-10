package rules

import (
	"embed"
	"fmt"
)

//go:embed bundled/*.yaml
var BundledRulesFS embed.FS

// NewDefaultEngine creates a RuleEngine preloaded with all built-in cryptographic detection rules.
func NewDefaultEngine() (*Engine, error) {
	engine := NewEngine()
	err := engine.LoadFromFS(BundledRulesFS, "bundled")
	if err != nil {
		return nil, fmt.Errorf("failed to load bundled rules: %w", err)
	}
	return engine, nil
}
