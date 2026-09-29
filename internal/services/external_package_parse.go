package services

import (
	"encoding/json"
	"strings"
)

// This file holds every externally-installed-ecosystem output parser
// (pip/npm/gem/snap) -- pure functions from raw command stdout to
// InstalledPackage, mirroring package_parse.go's shape. These ecosystems
// are list-only (no CheckUpdates/RefreshMetadata -- see
// ExternalPackageScanner's own doc comment), so there's no
// AvailableUpdate-style parser here, only installed-package listing.

// ParsePipFreeze parses `pip3 list --format=freeze`/`pip list --format=freeze`
// output: one "name==version" per line. Lines that don't contain "=="
// (blank lines, warnings printed to stdout by a misconfigured pip) are
// skipped rather than erroring the whole scan.
func ParsePipFreeze(output string) []InstalledPackage {
	var packages []InstalledPackage
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" {
			continue
		}
		packages = append(packages, InstalledPackage{Name: name, Version: version})
	}
	return packages
}

// npmListOutput mirrors the shape of `npm list -g --depth=0 --json`'s
// relevant fields -- everything else in npm's own output is ignored.
type npmListOutput struct {
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// ParseNpmListJSON parses `npm list -g --depth=0 --json` output. Malformed
// JSON (npm printed nothing, or an unexpected shape) yields an empty
// list rather than an error -- consistent with every other "external
// ecosystem missing/misbehaving" case being a skip, not a scan failure.
func ParseNpmListJSON(output string) []InstalledPackage {
	var parsed npmListOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil
	}
	packages := make([]InstalledPackage, 0, len(parsed.Dependencies))
	for name, dep := range parsed.Dependencies {
		if name == "" || dep.Version == "" {
			continue
		}
		packages = append(packages, InstalledPackage{Name: name, Version: dep.Version})
	}
	return packages
}

// ParseGemList parses `gem list --local` output: lines shaped like
// "bundler (2.4.10, 2.3.7)" -- a gem can have multiple installed
// versions; only the first (newest, gem lists newest-first) is kept,
// consistent with every other ecosystem here reporting one row per
// package name.
func ParseGemList(output string) []InstalledPackage {
	var packages []InstalledPackage
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "***") {
			continue
		}
		name, rest, ok := strings.Cut(line, " (")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		versions := strings.TrimSuffix(rest, ")")
		firstVersion, _, _ := strings.Cut(versions, ",")
		firstVersion = strings.TrimSpace(firstVersion)
		if name == "" || firstVersion == "" {
			continue
		}
		packages = append(packages, InstalledPackage{Name: name, Version: firstVersion})
	}
	return packages
}

// ParseSnapList parses `snap list` output: a header row ("Name  Version
// Rev  Tracking  Publisher  Notes") followed by one row per installed
// snap, whitespace-column-separated.
func ParseSnapList(output string) []InstalledPackage {
	lines := strings.Split(output, "\n")
	var packages []InstalledPackage
	for i, line := range lines {
		if i == 0 {
			continue // header row
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		packages = append(packages, InstalledPackage{Name: fields[0], Version: fields[1]})
	}
	return packages
}
