package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
)

type DSMMetadata struct {
	Version        string `json:"version,omitempty"`
	MajorVersion   string `json:"majorVersion,omitempty"`
	MinorVersion   string `json:"minorVersion,omitempty"`
	BuildNumber    string `json:"buildNumber,omitempty"`
	SmallFixNumber string `json:"smallFixNumber,omitempty"`
	Model          string `json:"model,omitempty"`
	Architecture   string `json:"architecture,omitempty"`
	IsDSM          bool   `json:"isDSM"`
	IsSupported    bool   `json:"isSupported"`
}

func collectMetadata(ctx context.Context, executor CommandExecutor, timeout time.Duration) (DSMMetadata, []string) {
	var warnings []string

	versionFile, versionErrors := collectFirstExisting(preferredDSMPaths("VERSION")...)
	warnings = append(warnings, prefixErrors("DSM version metadata", versionErrors)...)
	synoinfoFile, synoinfoErrors := collectFirstExisting(preferredDSMPaths("synoinfo.conf")...)
	warnings = append(warnings, prefixErrors("DSM system metadata", synoinfoErrors)...)
	hardwareFiles, hardwareErrors := collectFiles("/proc/sys/kernel/syno_hw_version")
	warnings = append(warnings, prefixErrors("DSM hardware metadata", hardwareErrors)...)

	var versionData, synoinfoData, hardwareData string
	if versionFile.Path != "" {
		versionData = versionFile.Content
	}
	if synoinfoFile.Path != "" {
		synoinfoData = synoinfoFile.Content
	}
	if len(hardwareFiles) == 1 {
		hardwareData = hardwareFiles[0].Content
	}

	metadata := parseDSMMetadata(versionData, synoinfoData, hardwareData)
	if metadata.Architecture == "" {
		commandCtx, cancel := context.WithTimeout(ctx, timeout)
		output, commandErr := executor.Run(commandCtx, "uname", "-m")
		cancel()
		if commandErr == nil {
			metadata.Architecture = strings.TrimSpace(output)
		} else {
			metadata.Architecture = runtime.GOARCH
			warnings = append(warnings, fmt.Sprintf("architecture fallback: %v", commandErr))
		}
	}

	return metadata, warnings
}

func prefixErrors(prefix string, errors []string) []string {
	prefixed := make([]string, 0, len(errors))
	for _, err := range errors {
		prefixed = append(prefixed, prefix+": "+err)
	}
	return prefixed
}

func parseDSMMetadata(versionData, synoinfoData, hardwareData string) DSMMetadata {
	version := parseKeyValues(versionData)
	synoinfo := parseKeyValues(synoinfoData)

	metadata := DSMMetadata{
		Version:        firstNonEmpty(version["productversion"], joinVersion(version["majorversion"], version["minorversion"])),
		MajorVersion:   version["majorversion"],
		MinorVersion:   version["minorversion"],
		BuildNumber:    version["buildnumber"],
		SmallFixNumber: version["smallfixnumber"],
		Model:          strings.TrimSpace(hardwareData),
		Architecture:   synoinfo["arch"],
	}
	if metadata.Model == "" {
		metadata.Model = firstNonEmpty(synoinfo["upnpmodelname"], synoinfo["modelname"])
	}
	metadata.IsDSM = metadata.MajorVersion != "" &&
		metadata.MinorVersion != "" &&
		(metadata.Version != "" || metadata.BuildNumber != "")
	metadata.IsSupported = metadata.IsDSM &&
		metadata.MajorVersion == "6" &&
		metadata.MinorVersion == "2"
	return metadata
}

func joinVersion(major, minor string) string {
	if major == "" || minor == "" {
		return ""
	}
	return major + "." + minor
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
