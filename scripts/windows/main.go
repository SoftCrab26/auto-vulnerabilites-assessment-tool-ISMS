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

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

func main() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown_host"
	}

	ip := getLocalIP()
	baseName := fmt.Sprintf("%s_%s", sanitize(hostname), sanitize(ip))

	cleanupStdout := setupStdoutLogging(baseName + ".stdout.log")
	defer cleanupStdout()

	runtime := collectRuntimeData()
	services := detectServices(runtime)
	ctx := ScanContext{
		Services: services,
		Runtime:  runtime,
	}

	fmt.Println()
	fmt.Println("================================")
	fmt.Println("[FINAL RESULT]")
	fmt.Println("================================")

	for key, service := range services {
		fmt.Println("--------------------------------")
		fmt.Println("KEY:", key)
		fmt.Println("NAME:", service.Name)
		fmt.Println("RUNNING:", service.Running)
		fmt.Println("LISTENING:", service.Listening)
		fmt.Println("VERSION:", service.Version)
		fmt.Println("PROCESS MATCHES:")
		for _, p := range service.ProcessMatches {
			fmt.Println("-", p)
		}
		fmt.Println("SERVICE MATCHES:")
		for _, s := range service.ServiceMatches {
			fmt.Println("-", s)
		}
		fmt.Println("LISTENING PORTS:")
		for _, port := range service.ListeningPorts {
			fmt.Println("-", port)
		}
		fmt.Println()
	}

	results := []CheckResult{
		checkW01(ctx),
		checkW02(ctx),
		checkW03(ctx),
		checkW04(ctx),
		checkW05(ctx),
		checkW06(ctx),
		checkW07(ctx),
		checkW08(ctx),
		checkW09(ctx),
		checkW10(ctx),
		checkW11(ctx),
		checkW12(ctx),
		checkW13(ctx),
		checkW14(ctx),
		checkW15(ctx),
		checkW16(ctx),
		checkW17(ctx),
		checkW18(ctx),
		checkW19(ctx),
		checkW20(ctx),
		checkW21(ctx),
		checkW22(ctx),
		checkW23(ctx),
		checkW24(ctx),
		checkW25(ctx),
		checkW26(ctx),
		checkW27(ctx),
		checkW28(ctx),
		checkW29(ctx),
		checkW30(ctx),
		checkW31(ctx),
		checkW32(ctx),
		checkW33(ctx),
		checkW34(ctx),
		checkW35(ctx),
		checkW36(ctx),
		checkW37(ctx),
		checkW38(ctx),
		checkW39(ctx),
		checkW40(ctx),
		checkW41(ctx),
		checkW42(ctx),
		checkW43(ctx),
	}

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

	fileName := baseName + ".json"

	jsonData, err := json.MarshalIndent(toJSONCheckResults(results), "", "  ")
	if err != nil {
		fmt.Println("JSON marshal error:", err)
		return
	}

	err = os.WriteFile(fileName, jsonData, 0644)
	if err != nil {
		fmt.Println("file write error:", err)
		return
	}

	fmt.Println("JSON saved to:", fileName)
	fmt.Println("STDOUT saved to:", baseName+".stdout.log")
}

func toJSONCheckResults(results []CheckResult) []JSONCheckResult {
	jsonResults := make([]JSONCheckResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, JSONCheckResult{
			OS:               "WINDOWS",
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

func setupStdoutLogging(path string) func() {
	stdout := os.Stdout
	file, err := os.Create(path)
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
