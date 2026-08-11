package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ScanContext struct {
	Metadata DSMMetadata
	Runtime  RuntimeData
	Services []Service
}

func runChecks(ctx ScanContext) []CheckResult {
	return []CheckResult{
		checkU01(ctx),
		checkU02(ctx),
		checkU03(ctx),
		checkU04(ctx),
		checkU05(ctx),
		checkU06(ctx),
		checkU07(ctx),
		checkU08(ctx),
		checkU09(ctx),
		checkU10(ctx),
		checkU11(ctx),
		checkU12(ctx),
		checkU13(ctx),
		checkU14(ctx),
		checkU15(ctx),
		checkU16(ctx),
		checkU17(ctx),
		checkU18(ctx),
		checkU19(ctx),
		checkU20(ctx),
		checkU21(ctx),
		checkU22(ctx),
		checkU23(ctx),
		checkU24(ctx),
		checkU25(ctx),
		checkU26(ctx),
		checkU27(ctx),
		checkU28(ctx),
		checkU29(ctx),
		checkU30(ctx),
		checkU31(ctx),
		checkU32(ctx),
		checkU33(ctx),
		checkU34(ctx),
		checkU35(ctx),
		checkU36(ctx),
		checkU37(ctx),
		checkU38(ctx),
		checkU39(ctx),
		checkU40(ctx),
		checkU41(ctx),
		checkU42(ctx),
		checkU43(ctx),
		checkU44(ctx),
		checkU45(ctx),
		checkU46(ctx),
		checkU47(ctx),
		checkU48(ctx),
		checkU49(ctx),
		checkU50(ctx),
		checkU51(ctx),
		checkU52(ctx),
		checkU53(ctx),
		checkU54(ctx),
		checkU55(ctx),
		checkU56(ctx),
		checkU57(ctx),
		checkU58(ctx),
		checkU59(ctx),
		checkU60(ctx),
		checkU61(ctx),
		checkU62(ctx),
		checkU63(ctx),
		checkU64(ctx),
		checkU65(ctx),
		checkU66(ctx),
		checkU67(ctx),
	}
}

func main() {
	if err := execute(context.Background(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, stdout io.Writer) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}

	executor := programExecutor{}
	metadata, metadataWarnings := collectMetadata(ctx, executor, config.CommandTimeout)
	runtimeData := collectRuntimeData(ctx, executor, config.CommandTimeout)
	scanContext := ScanContext{
		Metadata: metadata,
		Runtime:  runtimeData,
		Services: detectServices(runtimeData),
	}

	warnings := append([]string{}, metadataWarnings...)
	switch {
	case !metadata.IsDSM:
		warnings = append(warnings, "Synology DSM 환경을 확인할 수 없습니다. 결과를 지원 대상 진단으로 해석하지 마십시오.")
	case !metadata.IsSupported:
		warnings = append(warnings, "지원 대상은 Synology DSM 6.2.x뿐입니다. 현재 버전은 지원되지 않습니다.")
	}

	results := runChecks(scanContext)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown_host"
	}
	// Match Ubuntu / web UI test_data naming: {hostname}_{ip}.json
	baseName := fmt.Sprintf(
		"%s_%s",
		sanitizedFilename(hostname),
		sanitizedFilename(localIP()),
	)

	logLines := summaryLines(scanContext, warnings)
	for _, line := range logLines {
		fmt.Fprintln(stdout, line)
	}

	logPath := filepath.Join(config.OutputDir, baseName+".stdout.log")
	if err := writeExclusive(logPath, []byte(strings.Join(logLines, "\n")+"\n")); err != nil {
		return err
	}

	// JSON array of CheckResult — same schema as frontend/ui/test_data/*.json
	reportData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("encode scan report: %w", err)
	}
	reportData = append(reportData, '\n')
	reportPath := filepath.Join(config.OutputDir, baseName+".json")
	if err := writeExclusive(reportPath, reportData); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "보고서: %s\n로그: %s\n", reportPath, logPath)
	return nil
}

func summaryLines(scanContext ScanContext, warnings []string) []string {
	metadata := scanContext.Metadata
	lines := []string{
		"Synology DSM 취약점 진단 스캐너 기반 수집 완료",
		fmt.Sprintf("DSM 감지: %t", metadata.IsDSM),
		fmt.Sprintf("버전: %s (빌드 %s, 업데이트 %s)", displayValue(metadata.Version), displayValue(metadata.BuildNumber), displayValue(metadata.SmallFixNumber)),
		fmt.Sprintf("모델/아키텍처: %s / %s", displayValue(metadata.Model), displayValue(metadata.Architecture)),
		fmt.Sprintf("지원 대상(DSM 6.2.x): %t", metadata.IsSupported),
		fmt.Sprintf("서비스 감지 수: %d", activeServiceCount(scanContext.Services)),
		fmt.Sprintf("수집 오류 수: %d", len(scanContext.Runtime.Errors)),
		"진단 항목 수: 67 (U-01~U-67)",
	}
	for _, warning := range warnings {
		lines = append(lines, "경고: "+warning)
	}
	return lines
}

func activeServiceCount(services []Service) int {
	count := 0
	for _, service := range services {
		if service.IsActive {
			count++
		}
	}
	return count
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "확인 불가"
	}
	return value
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create output %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write output %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output %s: %w", path, err)
	}
	return nil
}
