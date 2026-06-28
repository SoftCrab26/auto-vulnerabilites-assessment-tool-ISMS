package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type KeyPairList struct {
	KeyPairs []struct {
		KeyName        string `json:"KeyName"`
		KeyFingerprint string `json:"KeyFingerprint"`
	} `json:"KeyPairs"`
}

type S3BucketList struct {
	Buckets []struct {
		Name         string `json:"Name"`
		CreationDate string `json:"CreationDate"`
	} `json:"Buckets"`
}

func checkAWS06(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-06", "1.6", "Key Pair 보관 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1552.001"}, mitigations: []string{"M1027"}}

	result := evalAWS06(ctx.Runtime.KeyPairs, ctx.Runtime.S3Buckets)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS06(keyPairsRaw, s3Raw string) CheckResult {
	exposedBuckets := detectExposedBuckets(s3Raw)
	keyCount := countKeyPairs(keyPairsRaw)
	processedConfig := buildProcessedConfig(fmt.Sprintf("key_pairs=%d", keyCount), fmt.Sprintf("exposed_buckets=%d", len(exposedBuckets)))

	if len(exposedBuckets) > 0 {
		vulnConfig := buildVulnerableConfig("문제점1: 퍼블릭 액세스 가능한 S3 버킷에서 Key 파일 발견", "exposed_buckets: "+strings.Join(exposedBuckets, ", "))
		return CheckResult{Status: StatusVulnerable, RawConfig: keyPairsRaw, ProcessedConfig: processedConfig, VulnerableConfig: vulnConfig}
	}

	return CheckResult{Status: StatusGood, RawConfig: keyPairsRaw, ProcessedConfig: processedConfig}
}

func countKeyPairs(raw string) int {
	var keyList KeyPairList
	if err := json.Unmarshal([]byte(raw), &keyList); err != nil {
		return 0
	}
	return len(keyList.KeyPairs)
}

func detectExposedBuckets(raw string) []string {
	var s3List S3BucketList
	var exposed []string
	if err := json.Unmarshal([]byte(raw), &s3List); err != nil {
		return exposed
	}

	publicPatterns := []string{"public", "temp", "test", "backup", "key", "pem"}
	for _, bucket := range s3List.Buckets {
		lowerName := strings.ToLower(bucket.Name)
		for _, pattern := range publicPatterns {
			if strings.Contains(lowerName, pattern) {
				exposed = append(exposed, bucket.Name)
				break
			}
		}
	}
	return exposed
}
