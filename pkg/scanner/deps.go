package scanner

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DiscoveredDep represents a resolved library dependency.
type DiscoveredDep struct {
	Name      string
	Version   string
	Ecosystem string
	FilePath  string
	Line      int
}

// ParseDependencies detects and parses dependency manifests in a file.
func ParseDependencies(filePath string) ([]DiscoveredDep, error) {
	base := filepath.Base(filePath)
	switch {
	case base == "pom.xml":
		return parsePomXML(filePath)
	case base == "build.gradle" || base == "build.gradle.kts":
		return parseGradle(filePath)
	case base == "requirements.txt":
		return parseRequirementsTxt(filePath)
	case base == "poetry.lock":
		return parsePoetryLock(filePath)
	case base == "go.mod":
		return parseGoMod(filePath)
	case base == "go.sum":
		return parseGoSum(filePath)
	case base == "package.json":
		return parsePackageJSON(filePath)
	case base == "package-lock.json":
		return parsePackageLockJSON(filePath)
	default:
		return nil, nil
	}
}

// pom.xml structures
type pomProject struct {
	XMLName      xml.Name        `xml:"project"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func parsePomXML(path string) ([]DiscoveredDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var proj pomProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}

	var results []DiscoveredDep
	for _, dep := range proj.Dependencies {
		key := fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID)
		results = append(results, DiscoveredDep{
			Name:      key,
			Version:   dep.Version,
			Ecosystem: "maven",
			FilePath:  path,
			Line:      1,
		})
	}
	return results, nil
}

// Gradle parser
var gradleDepRegex = regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly)\s*[\('"]+([^:'"\s]+):([^:'"\s]+):?([^:'"\s]*)[\)'"]+`)

func parseGradle(path string) ([]DiscoveredDep, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []DiscoveredDep
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		matches := gradleDepRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			group := matches[1]
			artifact := matches[2]
			version := ""
			if len(matches) >= 4 {
				version = matches[3]
			}
			results = append(results, DiscoveredDep{
				Name:      fmt.Sprintf("%s:%s", group, artifact),
				Version:   version,
				Ecosystem: "maven",
				FilePath:  path,
				Line:      lineNum,
			})
		}
	}
	return results, scanner.Err()
}

// requirements.txt parser
var reqRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)`)

func parseRequirementsTxt(path string) ([]DiscoveredDep, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []DiscoveredDep
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := reqRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			results = append(results, DiscoveredDep{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "pypi",
				FilePath:  path,
				Line:      lineNum,
			})
		} else if !strings.HasPrefix(line, "-") {
			// bare package name without version pinning
			results = append(results, DiscoveredDep{
				Name:      strings.Fields(line)[0],
				Version:   "",
				Ecosystem: "pypi",
				FilePath:  path,
				Line:      lineNum,
			})
		}
	}
	return results, scanner.Err()
}

// poetry.lock parser
func parsePoetryLock(path string) ([]DiscoveredDep, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []DiscoveredDep
	scanner := bufio.NewScanner(file)
	var currentName string
	var currentVer string
	var lineNum int
	var blockStartLine int

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if currentName != "" {
				results = append(results, DiscoveredDep{
					Name:      currentName,
					Version:   currentVer,
					Ecosystem: "pypi",
					FilePath:  path,
					Line:      blockStartLine,
				})
			}
			currentName = ""
			currentVer = ""
			blockStartLine = lineNum
			continue
		}
		if strings.HasPrefix(line, "name =") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				currentName = strings.Trim(strings.TrimSpace(parts[1]), "\"")
			}
		}
		if strings.HasPrefix(line, "version =") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				currentVer = strings.Trim(strings.TrimSpace(parts[1]), "\"")
			}
		}
	}
	if currentName != "" {
		results = append(results, DiscoveredDep{
			Name:      currentName,
			Version:   currentVer,
			Ecosystem: "pypi",
			FilePath:  path,
			Line:      blockStartLine,
		})
	}
	return results, scanner.Err()
}

// go.mod parser
var goModReq = regexp.MustCompile(`^\s*([^\s]+)\s+([v0-9a-zA-Z\.\-]+)`)

func parseGoMod(path string) ([]DiscoveredDep, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []DiscoveredDep
	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock || strings.HasPrefix(line, "require ") {
			target := line
			if strings.HasPrefix(line, "require ") {
				target = strings.TrimSpace(strings.TrimPrefix(line, "require"))
			}
			matches := goModReq.FindStringSubmatch(target)
			if len(matches) >= 3 {
				results = append(results, DiscoveredDep{
					Name:      matches[1],
					Version:   matches[2],
					Ecosystem: "golang",
					FilePath:  path,
					Line:      lineNum,
				})
			}
		}
	}
	return results, scanner.Err()
}

// go.sum parser
func parseGoSum(path string) ([]DiscoveredDep, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	var results []DiscoveredDep
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			pkg := fields[0]
			ver := fields[1]
			ver = strings.TrimSuffix(ver, "/go.mod")
			key := pkg + "@" + ver
			if !seen[key] {
				seen[key] = true
				results = append(results, DiscoveredDep{
					Name:      pkg,
					Version:   ver,
					Ecosystem: "golang",
					FilePath:  path,
					Line:      lineNum,
				})
			}
		}
	}
	return results, scanner.Err()
}

// package.json parser
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func parsePackageJSON(path string) ([]DiscoveredDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var results []DiscoveredDep
	for name, ver := range pkg.Dependencies {
		results = append(results, DiscoveredDep{
			Name:      name,
			Version:   ver,
			Ecosystem: "npm",
			FilePath:  path,
			Line:      1,
		})
	}
	for name, ver := range pkg.DevDependencies {
		results = append(results, DiscoveredDep{
			Name:      name,
			Version:   ver,
			Ecosystem: "npm",
			FilePath:  path,
			Line:      1,
		})
	}
	return results, nil
}

// package-lock.json parser (v2/v3 support)
type packageLockJSON struct {
	Packages     map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parsePackageLockJSON(path string) ([]DiscoveredDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var results []DiscoveredDep
	if len(lock.Packages) > 0 {
		for pkgPath, pkgInfo := range lock.Packages {
			if pkgPath == "" {
				continue
			}
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			results = append(results, DiscoveredDep{
				Name:      name,
				Version:   pkgInfo.Version,
				Ecosystem: "npm",
				FilePath:  path,
				Line:      1,
			})
		}
	} else {
		for name, dep := range lock.Dependencies {
			results = append(results, DiscoveredDep{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				FilePath:  path,
				Line:      1,
			})
		}
	}
	return results, nil
}
