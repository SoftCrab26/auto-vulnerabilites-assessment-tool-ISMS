package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

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
	return strings.ReplaceAll(s, " ", "_")
}

func main() {
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
		fmt.Println("LISTENING PORTS:")
		for _, port := range service.ListeningPorts {
			fmt.Println("-", port)
		}
		fmt.Println()
	}

	results := []CheckResult{
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

	// =========================
	// JSON FILE OUTPUT
	// =========================
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown_host"
	}

	ip := getLocalIP()

	fileName := fmt.Sprintf("%s_%s.json", sanitize(hostname), sanitize(ip))

	jsonData, err := json.MarshalIndent(results, "", "  ")
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
}
