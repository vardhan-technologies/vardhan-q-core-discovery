package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vardhan/qcore/pkg/model"
	"github.com/vardhan/qcore/pkg/rules"
)

// Scanner coordinates file discovery, dependency analysis, and rule matching.
type Scanner struct {
	ruleEngine *rules.Engine
	riskConfig model.RiskConfig
	version    string
}

// NewScanner instantiates a scanner with configured rules.
func NewScanner(engine *rules.Engine, version string) *Scanner {
	if version == "" {
		version = "0.1.0"
	}
	return &Scanner{
		ruleEngine: engine,
		riskConfig: model.DefaultRiskConfig(),
		version:    version,
	}
}

// SetRiskConfig configures the risk computation parameters.
func (s *Scanner) SetRiskConfig(cfg model.RiskConfig) {
	s.riskConfig = cfg
}

var ignoredDirectories = map[string]bool{
	".git":         true,
	".github":      true,
	"node_modules": true,
	"vendor":       true,
	"target":       true,
	"bin":          true,
	".idea":        true,
	".vscode":      true,
	"dist":         true,
	"build":        true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// ScanDirectory performs a full cryptographic discovery scan across the target directory.
func (s *Scanner) ScanDirectory(rootDir string) (*model.ScanReport, error) {
	startTime := time.Now()
	var findings []model.Finding
	assetMap := make(map[string]*model.CryptoAsset)
	filesScanned := 0

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if ignoredDirectories[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		filesScanned++
		relPath, _ := filepath.Rel(rootDir, path)
		if relPath == "" {
			relPath = path
		}

		// 1. Dependency Analysis for manifests & lockfiles
		deps, _ := ParseDependencies(path)
		for _, dep := range deps {
			if libInfo, isKnownCrypto := CapabilityDB[dep.Name]; isKnownCrypto {
				s.processDiscoveredLibrary(dep, libInfo, relPath, assetMap, &findings)
			}
		}

		// 2. Source Code Rule Scanning
		lang := rules.LanguageFromExtension(path)
		if lang != "" {
			fileFindings, fileAssets := s.scanSourceFile(path, relPath, lang)
			findings = append(findings, fileFindings...)
			for id, asset := range fileAssets {
				if existing, exists := assetMap[id]; exists {
					existing.Locations = append(existing.Locations, asset.Locations...)
				} else {
					assetMap[id] = asset
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	duration := time.Since(startTime)

	// Collect assets
	var assets []model.CryptoAsset
	for _, a := range assetMap {
		assets = append(assets, *a)
	}

	// Compute summary metrics
	summary := s.computeSummary(findings, assets)

	report := &model.ScanReport{
		Metadata: model.ScanMetadata{
			ToolName:        "Vardhan Q-Core",
			ToolVersion:     s.version,
			ScanTimestamp:   startTime,
			TargetDirectory: rootDir,
			FilesScanned:    filesScanned,
			DurationMs:      duration.Milliseconds(),
			RulesLoaded:     s.ruleEngine.Count(),
		},
		Summary:  summary,
		Assets:   assets,
		Findings: findings,
	}

	return report, nil
}

func (s *Scanner) scanSourceFile(absPath, relPath, lang string) ([]model.Finding, map[string]*model.CryptoAsset) {
	var findings []model.Finding
	fileAssets := make(map[string]*model.CryptoAsset)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return findings, fileAssets
	}
	content := string(data)

	applicableRules := s.ruleEngine.RulesForLanguage(lang)
	for _, rule := range applicableRules {
		matches := rule.ScanText(content)
		for _, match := range matches {
			riskScore := model.CalculateRiskScore(rule.Finding.Category, rule.Finding.Algorithm, s.riskConfig)

			findingID := fmt.Sprintf("%s-%s-%d", rule.ID, hashString(relPath)[:8], match.LineNumber)
			assetID := fmt.Sprintf("crypto:algo:%s", strings.ToLower(rule.Finding.Algorithm))

			sev := rule.Finding.Severity
			if sev == "" {
				if rule.Finding.QuantumVulnerable {
					sev = model.SeverityHigh
				} else if rule.Finding.Category == model.CategoryWeakClassical {
					sev = model.SeverityMedium
				} else {
					sev = model.SeverityInfo
				}
			}

			loc := model.Location{
				FilePath:  relPath,
				StartLine: match.LineNumber,
				EndLine:   match.LineNumber,
				Snippet:   strings.TrimSpace(match.LineText),
			}

			f := model.Finding{
				ID:                findingID,
				RuleID:            rule.ID,
				Title:             fmt.Sprintf("Use of %s (%s)", rule.Finding.Algorithm, rule.Finding.Category),
				Category:          rule.Finding.Category,
				Severity:          sev,
				Confidence:        model.ConfidenceHigh,
				QuantumVulnerable: rule.Finding.QuantumVulnerable,
				Algorithm:         rule.Finding.Algorithm,
				Location:          loc,
				Message:           rule.Finding.Message,
				Remediation:       rule.Finding.Remediation,
				References:        rule.Finding.References,
				RiskScore:         riskScore,
				AssetRef:          assetID,
			}
			findings = append(findings, f)

			// Asset tracking
			if _, exists := fileAssets[assetID]; !exists {
				prim := model.PrimitiveSignature
				if rule.Finding.Primitive != "" {
					prim = model.PrimitiveType(rule.Finding.Primitive)
				}
				fileAssets[assetID] = &model.CryptoAsset{
					ID:                assetID,
					Name:              rule.Finding.Algorithm,
					Primitive:         prim,
					QuantumVulnerable: rule.Finding.QuantumVulnerable,
					Locations:         []model.Location{loc},
					Confidence:        model.ConfidenceHigh,
				}
			} else {
				fileAssets[assetID].Locations = append(fileAssets[assetID].Locations, loc)
			}
		}
	}

	return findings, fileAssets
}

func (s *Scanner) processDiscoveredLibrary(dep DiscoveredDep, libInfo CryptoLibraryInfo, relPath string, assetMap map[string]*model.CryptoAsset, findings *[]model.Finding) {
	assetID := fmt.Sprintf("crypto:lib:%s", dep.Name)
	loc := model.Location{
		FilePath:  relPath,
		StartLine: dep.Line,
		Snippet:   fmt.Sprintf("%s @ %s", dep.Name, dep.Version),
	}

	isQuantumReady := libInfo.PQCStatus == PQCStatusSupported
	category := model.CategoryVulnerableDep
	severity := model.SeverityMedium
	qv := true

	if isQuantumReady {
		category = model.CategoryQuantumReady
		severity = model.SeverityInfo
		qv = false
	}

	remediation := fmt.Sprintf("Upgrade %s to a version supporting PQC (min recommended: %s) or wrap with a quantum-safe provider.", dep.Name, libInfo.MinPQCVer)
	if isQuantumReady {
		remediation = "Library already includes post-quantum cryptography support. Ensure PQC algorithms (e.g. ML-KEM, ML-DSA) are configured."
	}

	f := model.Finding{
		ID:                fmt.Sprintf("dep-%s-%d", hashString(dep.Name)[:8], dep.Line),
		RuleID:            "DEP-CRYPTO-LIB",
		Title:             fmt.Sprintf("Cryptographic library detected: %s (%s)", dep.Name, libInfo.PQCStatus),
		Category:          category,
		Severity:          severity,
		Confidence:        model.ConfidenceHigh,
		QuantumVulnerable: qv,
		Algorithm:         strings.Join(libInfo.Algorithms, ", "),
		Location:          loc,
		Message:           fmt.Sprintf("Dependency %s version %s identified. PQC Support: %s. Algorithms provided: %v", dep.Name, dep.Version, libInfo.PQCStatus, libInfo.Algorithms),
		Remediation:       remediation,
		References:        []string{"NIST Post-Quantum Cryptography Standardization", "CNSA 2.0 Timeline"},
		RiskScore:         model.CalculateRiskScore(category, dep.Name, s.riskConfig),
		AssetRef:          assetID,
	}
	*findings = append(*findings, f)

	if existing, exists := assetMap[assetID]; exists {
		existing.Locations = append(existing.Locations, loc)
	} else {
		assetMap[assetID] = &model.CryptoAsset{
			ID:                assetID,
			Name:              dep.Name,
			Library:           dep.Name,
			LibraryVersion:    dep.Version,
			Primitive:         model.PrimitiveKeyExchange,
			QuantumVulnerable: qv,
			Locations:         []model.Location{loc},
			Confidence:        model.ConfidenceHigh,
		}
	}
}

func (s *Scanner) computeSummary(findings []model.Finding, assets []model.CryptoAsset) model.ScanSummary {
	summary := model.ScanSummary{
		TotalFindings:  len(findings),
		SeverityCounts: make(map[string]int),
		AlgorithmMix:   make(map[string]int),
	}

	var totalRisk float64
	for _, f := range findings {
		summary.SeverityCounts[string(f.Severity)]++
		summary.AlgorithmMix[f.Algorithm]++
		totalRisk += f.RiskScore

		if f.RiskScore > summary.MaxRiskScore {
			summary.MaxRiskScore = f.RiskScore
		}

		if f.QuantumVulnerable {
			summary.QuantumVulnerableCount++
		} else if f.Category == model.CategoryWeakClassical {
			summary.WeakClassicalCount++
		} else if f.Category == model.CategoryQuantumReady {
			summary.QuantumReadyCount++
		}
	}

	if len(findings) > 0 {
		summary.AverageRiskScore = float64(int((totalRisk/float64(len(findings)))*10+0.5)) / 10
	}

	return summary
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
