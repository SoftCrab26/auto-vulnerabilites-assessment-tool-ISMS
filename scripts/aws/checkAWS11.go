package main

import (
	"encoding/json"
	"fmt"
)

type EKSClusterList struct {
	Clusters []string `json:"clusters"`
}

func checkAWS11(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-11", "1.11", "EKS 사용자 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := evalEKS(ctx.Runtime.EKSClusters, "ConfigMap(aws-auth) RBAC 설정 검토 필요\n인가된 사용자만 포함되어 있는지 확인: kubectl get configmap aws-auth -n kube-system")
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalEKS(raw, reviewNote string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{Status: StatusNotApplicable, RawConfig: raw, ProcessedConfig: buildProcessedConfig("no_eks_clusters")}
	}

	var clusterList EKSClusterList
	if err := json.Unmarshal([]byte(raw), &clusterList); err != nil {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("parse_error")}
	}

	processedConfig := buildProcessedConfig(fmt.Sprintf("eks_clusters=%d", len(clusterList.Clusters)))
	return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: "각 EKS 클러스터의\n" + reviewNote}
}
