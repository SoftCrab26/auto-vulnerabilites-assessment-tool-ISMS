package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type JSONCheckResult struct {
	OS               string
	Item             int
	Description      string
	Status           Status
	RawConfig        string
	VulnerableConfig string
	ProcessedConfig  string
	ErrMsg           string
	MitreAttack      MitreAttack
}

func main() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown_host"
	}
	baseName := fmt.Sprintf("%s_%s", sanitize(hostname), sanitize(getLocalIP()))

	cleanupStdout := setupStdoutLogging(baseName + ".stdout.log")
	defer cleanupStdout()

	runtimeData := collectRuntimeData()
	services := detectServices(runtimeData)
	ctx := ScanContext{Services: services, Runtime: runtimeData}

	printRuntimeSummary(runtimeData, services)

	results := runChecks(ctx)
	printCheckResults(results)

	jsonData, err := json.MarshalIndent(toJSONCheckResults(results), "", "  ")
	if err != nil {
		fmt.Println("JSON marshal error:", err)
		return
	}

	fileName := baseName + ".json"
	if err := os.WriteFile(fileName, jsonData, 0600); err != nil {
		fmt.Println("file write error:", err)
		return
	}

	fmt.Println("JSON saved to:", fileName)
	fmt.Println("STDOUT saved to:", baseName+".stdout.log")
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

func printRuntimeSummary(runtimeData RuntimeData, services map[string]Service) {
	fmt.Println()
	fmt.Println("================================")
	fmt.Println("[AIX RUNTIME]")
	fmt.Println("================================")
	fmt.Println("OSLEVEL:", runtimeData.OSLevel)
	for _, runtimeErr := range runtimeData.Errors {
		fmt.Println("RUNTIME ERROR:", runtimeErr)
	}

	for key, service := range services {
		fmt.Println("--------------------------------")
		fmt.Println("KEY:", key)
		fmt.Println("NAME:", service.Name)
		fmt.Println("RUNNING:", service.Running)
		fmt.Println("LISTENING:", service.Listening)
		fmt.Println("DETAIL:", formatServiceStatus(service))
	}
}

func printCheckResults(results []CheckResult) {
	fmt.Println()
	fmt.Println("================================")
	fmt.Println("[FINAL RESULT]")
	fmt.Println("================================")

	for _, result := range results {
		fmt.Println("--------------------------------")
		fmt.Println("CODE:", result.Code)
		fmt.Println("STATUS:", result.Status.toString())
		fmt.Println("DESCRIPTION:", result.Description)
		fmt.Println("PROCESSED:", result.ProcessedConfig)
		if result.VulnerableConfig != "" {
			fmt.Println("VULNERABLE CONFIG:")
			fmt.Println(result.VulnerableConfig)
		}
		if result.RawConfig != "" {
			fmt.Println("RAW CONFIG:")
			fmt.Println(result.RawConfig)
		}
		if result.ErrMsg != "" {
			fmt.Println("ERROR:", result.ErrMsg)
		}
	}
}

func toJSONCheckResults(results []CheckResult) []JSONCheckResult {
	jsonResults := make([]JSONCheckResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, JSONCheckResult{
			OS:               "AIX",
			Item:             parseCheckItem(result.Code),
			Description:      result.Description,
			Status:           result.Status,
			RawConfig:        result.RawConfig,
			VulnerableConfig: result.VulnerableConfig,
			ProcessedConfig:  result.ProcessedConfig,
			ErrMsg:           result.ErrMsg,
			MitreAttack:      result.MitreAttack,
		})
	}
	return jsonResults
}

func parseCheckItem(code string) int {
	parts := strings.Split(code, "-")
	if len(parts) != 2 {
		return 0
	}
	item, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return item
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "unknown"
}

func sanitize(value string) string {
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, ":", "_")
	return value
}

func setupStdoutLogging(path string) func() {
	stdout := os.Stdout
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("stdout log create error:", err)
		return func() {}
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		fmt.Println("stdout pipe create error:", err)
		_ = file.Close()
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.MultiWriter(stdout, file), reader)
		_ = reader.Close()
		_ = file.Close()
		close(done)
	}()

	os.Stdout = writer
	return func() {
		_ = writer.Close()
		<-done
		os.Stdout = stdout
	}
}
