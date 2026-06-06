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

	result := checkU01(services)
	println("CODE:", result.Code)
	println("RESULT:", result.Status)

	println("\nProcessed Config:")
	println(result.ProcessedConfig)
	println("\nRaw Config:")
	println(result.RawConfig)
	println("\nError Message:")
	println(result.ErrMsg)
}
