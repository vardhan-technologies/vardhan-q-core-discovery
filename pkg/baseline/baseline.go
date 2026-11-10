package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vardhan/qcore/pkg/model"
)

// ExceptionStatus indicates the state of an accepted finding.
type ExceptionStatus string

const (
	StatusAccepted ExceptionStatus = "ACCEPTED"
	StatusExpired  ExceptionStatus = "EXPIRED"
)

// BaselineException records an approved risk acceptance for a finding.
type BaselineException struct {
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"rule_id"`
	FilePath    string    `json:"file_path"`
	Algorithm   string    `json:"algorithm"`
	Reason      string    `json:"reason"`
	ApprovedBy  string    `json:"approved_by"`
	ApprovedAt  time.Time `json:"approved_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	TicketRef   string    `json:"ticket_ref,omitempty"`
}

// Baseline represents the persistent approved risk register.
type Baseline struct {
	Version    string                       `json:"version"`
	CreatedAt  time.Time                    `json:"created_at"`
	UpdatedAt  time.Time                    `json:"updated_at"`
	Exceptions map[string]BaselineException `json:"exceptions"` // Keyed by Fingerprint
}

// ComputeFingerprint creates a stable identifier for a finding across scans.
func ComputeFingerprint(filePath, ruleID, algorithm string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", filePath, ruleID, algorithm)))
	return hex.EncodeToString(h[:12])
}

// NewBaseline creates an empty baseline container.
func NewBaseline() *Baseline {
	return &Baseline{
		Version:    "1.0",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
		Exceptions: make(map[string]BaselineException),
	}
}

// Load loads a baseline from a JSON file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid baseline format: %w", err)
	}
	if b.Exceptions == nil {
		b.Exceptions = make(map[string]BaselineException)
	}
	return &b, nil
}

// Save writes the baseline to a JSON file.
func (b *Baseline) Save(path string) error {
	b.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// BaselineResult captures how the baseline modified the scan report.
type BaselineResult struct {
	ActiveExceptions   int
	ExpiredExceptions  int
	SuppressedFindings int
}

// Apply reconciles a scan report against approved exceptions.
func (b *Baseline) Apply(report *model.ScanReport) BaselineResult {
	res := BaselineResult{}
	now := time.Now().UTC()

	var activeFindings []model.Finding

	for _, f := range report.Findings {
		fp := ComputeFingerprint(f.Location.FilePath, f.RuleID, f.Algorithm)

		if exc, exists := b.Exceptions[fp]; exists {
			// Check expiration
			if !exc.ExpiresAt.IsZero() && now.After(exc.ExpiresAt) {
				// Expired exception!
				f.Title = fmt.Sprintf("[EXPIRED EXCEPTION] %s", f.Title)
				f.Message = fmt.Sprintf("Risk acceptance expired on %s. Original reason: %s. %s",
					exc.ExpiresAt.Format("2006-01-02"), exc.Reason, f.Message)
				res.ExpiredExceptions++
				activeFindings = append(activeFindings, f)
			} else {
				// Active, valid exception
				res.ActiveExceptions++
				res.SuppressedFindings++
				// Do not count in active quantum-vulnerable count for CI breaks
				if f.QuantumVulnerable {
					report.Summary.QuantumVulnerableCount--
				}
				// Keep in audit findings list but flag as suppressed
				f.Severity = model.SeverityInfo
				f.Title = fmt.Sprintf("[ACCEPTED RISK] %s", f.Title)
				f.Message = fmt.Sprintf("Risk accepted by %s: '%s'. %s", exc.ApprovedBy, exc.Reason, f.Message)
				activeFindings = append(activeFindings, f)
			}
		} else {
			activeFindings = append(activeFindings, f)
		}
	}

	report.Findings = activeFindings
	return res
}

// CreateFromReport snapshots findings from a report into a new baseline.
func CreateFromReport(report *model.ScanReport, approvedBy, reason string, validityDays int) *Baseline {
	b := NewBaseline()
	now := time.Now().UTC()
	var expiry time.Time
	if validityDays > 0 {
		expiry = now.Add(time.Duration(validityDays) * 24 * time.Hour)
	}

	for _, f := range report.Findings {
		// Only baseline actual risks, not positive quantum-ready findings
		if f.Category == model.CategoryQuantumReady {
			continue
		}
		fp := ComputeFingerprint(f.Location.FilePath, f.RuleID, f.Algorithm)
		b.Exceptions[fp] = BaselineException{
			Fingerprint: fp,
			RuleID:      f.RuleID,
			FilePath:    f.Location.FilePath,
			Algorithm:   f.Algorithm,
			Reason:      reason,
			ApprovedBy:  approvedBy,
			ApprovedAt:  now,
			ExpiresAt:   expiry,
		}
	}
	return b
}
