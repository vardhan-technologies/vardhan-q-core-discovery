package rules

import (
	"fmt"
	"regexp"

	"github.com/vardhan/qcore/pkg/model"
)

// RuleFinding describes the finding metadata generated when a rule matches.
type RuleFinding struct {
	Category          model.Category `yaml:"category"`
	Algorithm         string         `yaml:"algorithm"`
	Primitive         string         `yaml:"primitive,omitempty"` // signature, key-exchange, hash, etc.
	QuantumVulnerable bool           `yaml:"quantum_vulnerable"`
	Severity          model.Severity `yaml:"severity,omitempty"`
	Message           string         `yaml:"message"`
	Remediation       string         `yaml:"remediation,omitempty"`
	References        []string       `yaml:"references,omitempty"`
}

// RuleTests defines unit tests for the rule.
type RuleTests struct {
	MustMatch    []string `yaml:"must_match"`
	MustNotMatch []string `yaml:"must_not_match"`
}

// Rule represents a declarative cryptographic detection rule.
type Rule struct {
	ID        string      `yaml:"id"`
	Language  string      `yaml:"language"` // "go", "python", "java", "javascript", "typescript", "generic", "any"
	Pattern   string      `yaml:"pattern,omitempty"`
	Regex     string      `yaml:"regex,omitempty"`
	Imports   []string    `yaml:"imports,omitempty"`
	Finding   RuleFinding `yaml:"finding"`
	Tests     RuleTests   `yaml:"tests,omitempty"`

	// Compiled regex internal cache
	compiledRegex *regexp.Regexp
}

// Compile prepares the rule regex for evaluation.
func (r *Rule) Compile() error {
	var patternStr string
	if r.Regex != "" {
		patternStr = r.Regex
	} else if r.Pattern != "" {
		// Convert simple wildcard / syntax patterns to regex if needed
		patternStr = r.Pattern
	} else {
		return fmt.Errorf("rule %s has neither pattern nor regex defined", r.ID)
	}

	compiled, err := regexp.Compile(patternStr)
	if err != nil {
		return fmt.Errorf("rule %s failed to compile regex '%s': %w", r.ID, patternStr, err)
	}
	r.compiledRegex = compiled
	return nil
}

// Matches returns true if the text matches the rule pattern.
func (r *Rule) Matches(text string) bool {
	if r.compiledRegex == nil {
		if err := r.Compile(); err != nil {
			return false
		}
	}
	return r.compiledRegex.MatchString(text)
}

// FindMatches returns line matches (line index 1-based, matched text)
type MatchResult struct {
	LineNumber int
	LineText   string
	MatchText  string
}

// ScanText searches multi-line text and returns all line matches.
func (r *Rule) ScanText(text string) []MatchResult {
	if r.compiledRegex == nil {
		if err := r.Compile(); err != nil {
			return nil
		}
	}

	var results []MatchResult
	lines := splitLines(text)
	for i, line := range lines {
		if r.compiledRegex.MatchString(line) {
			match := r.compiledRegex.FindString(line)
			results = append(results, MatchResult{
				LineNumber: i + 1,
				LineText:   line,
				MatchText:  match,
			})
		}
	}
	return results
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
