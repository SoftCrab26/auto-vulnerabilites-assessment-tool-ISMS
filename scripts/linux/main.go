package main

import "fmt"

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
		fmt.Println("STATUS:", result.Status)
		fmt.Println("DESCRIPTION:", result.Description)
		fmt.Println("PROCESSED:", result.ProcessedConfig)
		if result.RawConfig != "" {
			fmt.Println("RAW CONFIG:")
			fmt.Println(result.RawConfig)
		}
		if result.ErrMsg != "" {
			fmt.Println("ERROR:", result.ErrMsg)
		}
	}
}
