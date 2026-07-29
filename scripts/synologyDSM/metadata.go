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

	versionFile, err := collectFirstExisting("/etc/VERSION", "/etc.defaults/VERSION")
	if err != nil {
		warnings = append(warnings, "DSM version metadata: "+err.Error())
	}
	synoinfoFile, err := collectFirstExisting("/etc/synoinfo.conf", "/etc.defaults/synoinfo.conf")
	if err != nil {
		warnings = append(warnings, "DSM system metadata: "+err.Error())
	}
	hardwareFile := collectFiles("/proc/sys/kernel/syno_hw_version")
	if len(hardwareFile) == 1 && hardwareFile[0].Err != nil {
		warnings = append(warnings, "DSM hardware metadata: "+hardwareFile[0].Err.Error())
	}

	var versionData, synoinfoData, hardwareData string
	if versionFile.Err == nil {
		versionData = string(versionFile.Data)
	}
	if synoinfoFile.Err == nil {
		synoinfoData = string(synoinfoFile.Data)
	}
	if len(hardwareFile) == 1 && hardwareFile[0].Err == nil {
		hardwareData = string(hardwareFile[0].Data)
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
		Architecture:   firstNonEmpty(synoinfo["arch"], architectureFromUnique(synoinfo["unique"])),
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

func architectureFromUnique(unique string) string {
	unique = strings.TrimSpace(unique)
	if unique == "" {
		return ""
	}
	if index := strings.IndexByte(unique, '_'); index >= 0 && index+1 < len(unique) {
		return unique[index+1:]
	}
	return unique
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
