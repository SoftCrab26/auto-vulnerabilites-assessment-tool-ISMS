package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type JSONCheckResult struct {
	OS               string
	Item             int
	GuideCode        string
	Description      string
	Status           Status
	RawConfig        string
	VulnerableConfig string
	ProcessedConfig  string
	ErrMsg           string
	MitreAttack      MitreAttack
}

func sanitize(s string) string {
	return strings.ReplaceAll(s, " ", "_")
}

func main() {
	runtime := collectAWSRuntimeData()
	resources := detectAWSResources(runtime)
	ctx := ScanContext{
		Resources: resources,
		Runtime:   runtime,
	}

	accountID := runtime.AccountID
	if accountID == "" {
		accountID = "unknown_account"
	}
	region := runtime.Region
	if region == "" {
		region = "unknown_region"
	}

	baseName := fmt.Sprintf("%s_%s", sanitize(accountID), sanitize(region))

	cleanupStdout := setupStdoutLogging(baseName + ".stdout.log")
	defer cleanupStdout()

	fmt.Println()
	fmt.Println("================================")
	fmt.Println("[FINAL RESULT]")
	fmt.Println("================================")

	for key, resource := range resources {
		fmt.Println("--------------------------------")
		fmt.Println("KEY:", key)
		fmt.Println("NAME:", resource.Name)
		fmt.Println("AVAILABLE:", resource.Available)
		fmt.Println("SUMMARY:", resource.Summary)
		fmt.Println()
	}

	results := []CheckResult{
		checkAWS01(ctx),
		checkAWS02(ctx),
		checkAWS03(ctx),
		checkAWS04(ctx),
		checkAWS05(ctx),
		checkAWS06(ctx),
		checkAWS07(ctx),
		checkAWS08(ctx),
		checkAWS09(ctx),
		checkAWS10(ctx),
		checkAWS11(ctx),
		checkAWS12(ctx),
		checkAWS13(ctx),
		checkAWS14(ctx),
		checkAWS15(ctx),
		checkAWS16(ctx),
		checkAWS17(ctx),
		checkAWS18(ctx),
		checkAWS19(ctx),
		checkAWS20(ctx),
		checkAWS21(ctx),
		checkAWS22(ctx),
		checkAWS23(ctx),
		checkAWS24(ctx),
		checkAWS25(ctx),
		checkAWS26(ctx),
		checkAWS27(ctx),
		checkAWS28(ctx),
		checkAWS29(ctx),
		checkAWS30(ctx),
		checkAWS31(ctx),
		checkAWS32(ctx),
		checkAWS33(ctx),
		checkAWS34(ctx),
		checkAWS35(ctx),
		checkAWS36(ctx),
		checkAWS37(ctx),
		checkAWS38(ctx),
		checkAWS39(ctx),
		checkAWS40(ctx),
		checkAWS41(ctx),
		checkAWS42(ctx),
		checkAWS43(ctx),
		checkAWS44(ctx),
		checkAWS45(ctx),
		checkAWS46(ctx),
		checkAWS47(ctx),
		checkAWS48(ctx),
		checkAWS49(ctx),
		checkAWS50(ctx),
		checkAWS51(ctx),
		checkAWS52(ctx),
		checkAWS53(ctx),
		checkAWS54(ctx),
		checkAWS55(ctx),
		checkAWS56(ctx),
		checkAWS57(ctx),
		checkAWS58(ctx),
		checkAWS59(ctx),
		checkAWS60(ctx),
		checkAWS61(ctx),
		checkAWS62(ctx),
		checkAWS63(ctx),
	}

	for _, result := range results {
		fmt.Println("--------------------------------")
		fmt.Println("CODE:", result.Code)
		if result.GuideCode != "" {
			fmt.Println("GUIDE:", result.GuideCode)
		}
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
			OS:               "AWS",
			Item:             parseCheckItem(result.Code),
			GuideCode:        result.GuideCode,
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
