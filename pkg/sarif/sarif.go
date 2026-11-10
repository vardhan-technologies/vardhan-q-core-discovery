package sarif

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/vardhan/qcore/pkg/model"
)

// SARIF 2.1.0 Output Models for GitHub Code Scanning integration

type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     MultiformatString    `json:"shortDescription"`
	FullDescription      MultiformatString    `json:"fullDescription"`
	Help                 MultiformatString    `json:"help"`
	HelpURI              string               `json:"helpUri,omitempty"`
	DefaultConfiguration DefaultConfiguration `json:"defaultConfiguration"`
	Properties           RuleProperties       `json:"properties"`
}

type DefaultConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type RuleProperties struct {
	Tags      []string `json:"tags"`
	Precision string   `json:"precision"`
	Problem   struct {
		Severity string `json:"severity"`
	} `json:"problem,omitempty"`
}

type Result struct {
	RuleID    string             `json:"ruleId"`
	Level     string             `json:"level"` // "error", "warning", "note"
	Message   MultiformatString  `json:"message"`
	Locations []PhysicalLocation `json:"locations"`
}

type PhysicalLocation struct {
	PhysicalLocation LocationDescriptor `json:"physicalLocation"`
}

type LocationDescriptor struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI   string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type Region struct {
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine,omitempty"`
	SnippetText string `json:"snippet,omitempty"`
}

type MultiformatString struct {
	Text string `json:"text"`
}

func mapSeverityToSARIFLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// GenerateSARIF generates a SARIF 2.1.0 document from a ScanReport.
func GenerateSARIF(report *model.ScanReport) (*Report, error) {
	ruleMap := make(map[string]Rule)
	var results []Result

	for _, f := range report.Findings {
		level := mapSeverityToSARIFLevel(f.Severity)

		if _, exists := ruleMap[f.RuleID]; !exists {
			ruleMap[f.RuleID] = Rule{
				ID:   f.RuleID,
				Name: f.Title,
				ShortDescription: MultiformatString{
					Text: f.Title,
				},
				FullDescription: MultiformatString{
					Text: f.Message,
				},
				Help: MultiformatString{
					Text: f.Remediation,
				},
				HelpURI: "https://csrc.nist.gov/projects/post-quantum-cryptography",
				DefaultConfiguration: DefaultConfiguration{
					Level: level,
				},
				Properties: RuleProperties{
					Tags: []string{
						"security",
						"cryptography",
						string(f.Category),
					},
					Precision: strings.ToLower(string(f.Confidence)),
				},
			}
		}

		res := Result{
			RuleID: f.RuleID,
			Level:  level,
			Message: MultiformatString{
				Text: f.Message,
			},
			Locations: []PhysicalLocation{
				{
					PhysicalLocation: LocationDescriptor{
						ArtifactLocation: ArtifactLocation{
							URI: f.Location.FilePath,
						},
						Region: Region{
							StartLine: f.Location.StartLine,
							EndLine:   f.Location.EndLine,
						},
					},
				},
			},
		}
		results = append(results, res)
	}

	var rules []Rule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	sarifDoc := &Report{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Vardhan Q-Core",
						Version:        report.Metadata.ToolVersion,
						InformationURI: "https://github.com/vardhan/qcore",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return sarifDoc, nil
}

// ToJSON serializes SARIF to JSON.
func ToJSON(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
