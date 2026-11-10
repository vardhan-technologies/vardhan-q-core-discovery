package cbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/vardhan/qcore/pkg/model"
)

// CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Data Structures

type BOM struct {
	BOMFormat    string     `json:"bomFormat"`
	SpecVersion  string     `json:"specVersion"`
	SerialNumber string     `json:"serialNumber"`
	Version      int        `json:"version"`
	Metadata     Metadata   `json:"metadata"`
	Components   []Component`json:"components"`
}

type Metadata struct {
	Timestamp time.Time    `json:"timestamp"`
	Tools     Tools        `json:"tools"`
	Component *RootProject `json:"component,omitempty"`
}

type Tools struct {
	Components []ToolComponent `json:"components"`
}

type ToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type RootProject struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Component struct {
	BOMRef           string            `json:"bom-ref"`
	Type             string            `json:"type"` // "cryptographic-asset"
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"` // "algorithm", "certificate", "protocol"
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *ProtocolProperties  `json:"protocolProperties,omitempty"`
}

type AlgorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"` // "signature", "key-exchange", "pke", "block-cipher", "hash"
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	ExecutionEnvironment    string   `json:"executionEnvironment,omitempty"` // "software-plain-text"
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int      `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int      `json:"nistQuantumSecurityLevel"` // 0 for quantum vulnerable, 1-5 for PQC
}

type ProtocolProperties struct {
	Type         string   `json:"type"`
	Version      string   `json:"version,omitempty"`
	CipherSuites []string `json:"cipherSuites,omitempty"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

type Occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GenerateCBOM converts a ScanReport into a CycloneDX 1.6 CBOM document.
func GenerateCBOM(report *model.ScanReport, projectName string) (*BOM, error) {
	if projectName == "" {
		projectName = "target-codebase"
	}

	// Generate deterministic serial number based on project name and scan timestamp
	hash := sha256.Sum256([]byte(projectName + report.Metadata.ScanTimestamp.Format(time.RFC3339)))
	serialUUID := fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s",
		hex.EncodeToString(hash[0:4]),
		hex.EncodeToString(hash[4:6]),
		hex.EncodeToString(hash[6:8]),
		hex.EncodeToString(hash[8:10]),
		hex.EncodeToString(hash[10:16]),
	)

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: serialUUID,
		Version:      1,
		Metadata: Metadata{
			Timestamp: report.Metadata.ScanTimestamp.UTC(),
			Tools: Tools{
				Components: []ToolComponent{
					{
						Type:    "application",
						Name:    "Vardhan Q-Core",
						Version: report.Metadata.ToolVersion,
					},
				},
			},
			Component: &RootProject{
				Type: "application",
				Name: projectName,
			},
		},
		Components: make([]Component, 0, len(report.Assets)),
	}

	for _, asset := range report.Assets {
		var occurrences []Occurrence
		for _, loc := range asset.Locations {
			occurrences = append(occurrences, Occurrence{
				Location: loc.FilePath,
				Line:     loc.StartLine,
			})
		}

		// Sort occurrences deterministically
		sort.Slice(occurrences, func(i, j int) bool {
			if occurrences[i].Location == occurrences[j].Location {
				return occurrences[i].Line < occurrences[j].Line
			}
			return occurrences[i].Location < occurrences[j].Location
		})

		qLevel := asset.NISTQuantumSecurityLevel
		if asset.QuantumVulnerable {
			qLevel = 0
		}

		comp := Component{
			BOMRef:      asset.ID,
			Type:        "cryptographic-asset",
			Name:        asset.Name,
			Version:     asset.ParameterSetIdentifier,
			Description: fmt.Sprintf("%s cryptographic usage in %s", asset.Name, asset.Library),
			CryptoProperties: &CryptoProperties{
				AssetType: "algorithm",
				AlgorithmProperties: &AlgorithmProperties{
					Primitive:                string(asset.Primitive),
					ParameterSetIdentifier:   asset.ParameterSetIdentifier,
					ExecutionEnvironment:    "software-plain-text",
					ClassicalSecurityLevel:   asset.ClassicalSecurityLevel,
					NISTQuantumSecurityLevel: qLevel,
				},
			},
			Evidence: &Evidence{
				Occurrences: occurrences,
			},
			Properties: []Property{
				{
					Name:  "qcore:quantum-vulnerable",
					Value: fmt.Sprintf("%t", asset.QuantumVulnerable),
				},
				{
					Name:  "qcore:confidence",
					Value: string(asset.Confidence),
				},
			},
		}

		if asset.Library != "" {
			comp.Properties = append(comp.Properties, Property{
				Name:  "qcore:library",
				Value: asset.Library,
			})
		}
		if asset.LibraryVersion != "" {
			comp.Properties = append(comp.Properties, Property{
				Name:  "qcore:library-version",
				Value: asset.LibraryVersion,
			})
		}

		bom.Components = append(bom.Components, comp)
	}

	// Deterministic sorting of components by BOMRef for stable diffing
	sort.Slice(bom.Components, func(i, j int) bool {
		return bom.Components[i].BOMRef < bom.Components[j].BOMRef
	})

	return bom, nil
}

// ToJSON serializes the CBOM to formatted JSON.
func ToJSON(bom *BOM) ([]byte, error) {
	return json.MarshalIndent(bom, "", "  ")
}
