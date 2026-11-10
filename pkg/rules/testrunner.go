package rules

import (
	"fmt"
)

// RuleTestFailure records a specific test case failure for a rule.
type RuleTestFailure struct {
	RuleID  string
	Reason  string
	Fixture string
}

// TestResult summarizes rule verification.
type TestResult struct {
	TotalRules   int
	PassedTests  int
	FailedTests  int
	Failures     []RuleTestFailure
}

// TestAllRules runs positive (must_match) and negative (must_not_match) fixtures across all rules.
func (e *Engine) TestAllRules() TestResult {
	res := TestResult{
		TotalRules: len(e.rules),
	}

	for _, r := range e.rules {
		// Requirement: Every rule must have positive and negative fixtures
		if len(r.Tests.MustMatch) == 0 {
			res.Failures = append(res.Failures, RuleTestFailure{
				RuleID: r.ID,
				Reason: "Missing required positive test fixture (must_match)",
			})
			res.FailedTests++
			continue
		}
		if len(r.Tests.MustNotMatch) == 0 {
			res.Failures = append(res.Failures, RuleTestFailure{
				RuleID: r.ID,
				Reason: "Missing required negative test fixture (must_not_match)",
			})
			res.FailedTests++
			continue
		}

		// Positive tests
		rulePassed := true
		for _, fixture := range r.Tests.MustMatch {
			if !r.Matches(fixture) {
				res.Failures = append(res.Failures, RuleTestFailure{
					RuleID:  r.ID,
					Reason:  "Expected rule to MATCH fixture, but it did not",
					Fixture: fixture,
				})
				rulePassed = false
				res.FailedTests++
			}
		}

		// Negative tests
		for _, fixture := range r.Tests.MustNotMatch {
			if r.Matches(fixture) {
				res.Failures = append(res.Failures, RuleTestFailure{
					RuleID:  r.ID,
					Reason:  "Expected rule to NOT MATCH fixture, but it matched",
					Fixture: fixture,
				})
				rulePassed = false
				res.FailedTests++
			}
		}

		if rulePassed {
			res.PassedTests++
		}
	}

	return res
}

func (tr TestResult) String() string {
	if len(tr.Failures) == 0 {
		return fmt.Sprintf("All %d rules passed verification (%d total passed).", tr.TotalRules, tr.PassedTests)
	}
	s := fmt.Sprintf("Rule testing finished with %d failures out of %d rules:\n", len(tr.Failures), tr.TotalRules)
	for _, f := range tr.Failures {
		if f.Fixture != "" {
			s += fmt.Sprintf("  - [%s] %s: '%s'\n", f.RuleID, f.Reason, f.Fixture)
		} else {
			s += fmt.Sprintf("  - [%s] %s\n", f.RuleID, f.Reason)
		}
	}
	return s
}
