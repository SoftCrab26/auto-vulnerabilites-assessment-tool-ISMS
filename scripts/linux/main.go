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
		checkU01(services),
		checkU02(),
		checkU03(),
		checkU04(),
		checkU05(),
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
