package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Engine manages cryptographic detection rules.
type Engine struct {
	rules []*Rule
}

// NewEngine initializes a new rule engine.
func NewEngine() *Engine {
	return &Engine{
		rules: make([]*Rule, 0),
	}
}

// AddRule compiles and adds a rule to the engine.
func (e *Engine) AddRule(r *Rule) error {
	if err := r.Compile(); err != nil {
		return err
	}
	e.rules = append(e.rules, r)
	return nil
}

// Rules returns all loaded rules.
func (e *Engine) Rules() []*Rule {
	return e.rules
}

// Count returns the number of active rules.
func (e *Engine) Count() int {
	return len(e.rules)
}

// LoadYAMLBytes parses YAML containing a slice of rules or a single rule.
func (e *Engine) LoadYAMLBytes(data []byte) error {
	// First try decoding as slice of rules
	var ruleList []*Rule
	if err := yaml.Unmarshal(data, &ruleList); err == nil && len(ruleList) > 0 {
		for _, r := range ruleList {
			if err := e.AddRule(r); err != nil {
				return err
			}
		}
		return nil
	}

	// Try single rule
	var singleRule Rule
	if err := yaml.Unmarshal(data, &singleRule); err == nil && singleRule.ID != "" {
		return e.AddRule(&singleRule)
	}

	return fmt.Errorf("unable to parse rule YAML")
}

// LoadFromFS recursively loads all YAML rules from a filesystem.
func (e *Engine) LoadFromFS(fileSystem fs.FS, root string) error {
	return fs.WalkDir(fileSystem, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			content, err := fs.ReadFile(fileSystem, path)
			if err != nil {
				return fmt.Errorf("failed reading %s: %w", path, err)
			}
			if err := e.LoadYAMLBytes(content); err != nil {
				return fmt.Errorf("failed loading rules from %s: %w", path, err)
			}
		}
		return nil
	})
}

// LoadFromDir recursively loads all YAML rules from a directory path.
func (e *Engine) LoadFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed reading %s: %w", path, err)
			}
			if err := e.LoadYAMLBytes(content); err != nil {
				return fmt.Errorf("failed loading rules from %s: %w", path, err)
			}
		}
		return nil
	})
}

// RulesForLanguage returns rules that apply to a specific language or all languages.
func (e *Engine) RulesForLanguage(lang string) []*Rule {
	var matched []*Rule
	lang = strings.ToLower(lang)
	for _, r := range e.rules {
		rLang := strings.ToLower(r.Language)
		if rLang == "all" || rLang == "generic" || rLang == "any" || rLang == lang {
			matched = append(matched, r)
		}
	}
	return matched
}

// LanguageFromExtension maps file extension to supported language.
func LanguageFromExtension(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return "go"
	case ".py", ".pyw":
		return "python"
	case ".java":
		return "java"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".mts", ".cts":
		return "typescript"
	default:
		return ""
	}
}
