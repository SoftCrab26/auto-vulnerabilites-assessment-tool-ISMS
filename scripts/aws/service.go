package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type ScanContext struct {
	Resources map[string]AWSResource
	Runtime   AWSRuntimeData
}

type AWSRuntimeData struct {
	AccountID              string
	Region                 string
	CallerIdentity         string
	IAMUsers               string
	IAMGroups              string
	CredentialReport       string
	PasswordPolicy         string
	KeyPairs               string
	SecurityGroups         string
	NetworkACLs            string
	RouteTables            string
	InternetGateways       string
	NATGateways            string
	S3Buckets              string
	RDSSubnetGroups        string
	RDSInstances           string
	LoadBalancers          string
	EBSEncryptionByDefault string
	EBSVolumes             string
	CloudTrails            string
	VPCFlowLogs            string
	EKSClusters            string
	CollectionErrors       []string
}

type AWSResource struct {
	Name      string
	Available bool
	Summary   string
}

func runAWS(args ...string) string {
	fmt.Println("[EXEC]", "aws", strings.Join(args, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "aws", args...)

	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("[TIMEOUT]", strings.Join(args, " "))
		return ""
	}

	if err != nil {
		fmt.Println("[ERROR]", err.Error())
		if text != "" {
			fmt.Println(text)
		}
		return text
	}

	fmt.Println("[DONE]", args[0], args[1])
	return text
}

func collectAWSRuntimeData() AWSRuntimeData {
	fmt.Println("================================")
	fmt.Println("[*] Collecting AWS runtime data...")
	fmt.Println("================================")

	runtime := AWSRuntimeData{
		CallerIdentity: runAWS("sts", "get-caller-identity", "--output", "json"),
		Region:         strings.TrimSpace(runAWS("configure", "get", "region")),
	}

	runtime.AccountID = extractJSONField(runtime.CallerIdentity, "Account")
	if runtime.Region == "" {
		runtime.Region = "unknown"
	}

	_ = runAWS("iam", "generate-credential-report")

	runtime.IAMUsers = runAWS("iam", "list-users", "--output", "json")
	runtime.IAMGroups = runAWS("iam", "list-groups", "--output", "json")
	runtime.CredentialReport = runAWS("iam", "get-credential-report", "--query", "Content", "--output", "text")
	runtime.PasswordPolicy = runAWS("iam", "get-account-password-policy", "--output", "json")
	runtime.KeyPairs = runAWS("ec2", "describe-key-pairs", "--output", "json")
	runtime.SecurityGroups = runAWS("ec2", "describe-security-groups", "--output", "json")
	runtime.NetworkACLs = runAWS("ec2", "describe-network-acls", "--output", "json")
	runtime.RouteTables = runAWS("ec2", "describe-route-tables", "--output", "json")
	runtime.InternetGateways = runAWS("ec2", "describe-internet-gateways", "--output", "json")
	runtime.NATGateways = runAWS("ec2", "describe-nat-gateways", "--output", "json")
	runtime.S3Buckets = runAWS("s3api", "list-buckets", "--output", "json")
	runtime.RDSSubnetGroups = runAWS("rds", "describe-db-subnet-groups", "--output", "json")
	runtime.RDSInstances = runAWS("rds", "describe-db-instances", "--output", "json")
	runtime.LoadBalancers = runAWS("elbv2", "describe-load-balancers", "--output", "json")
	runtime.EBSEncryptionByDefault = runAWS("ec2", "get-ebs-encryption-by-default", "--output", "json")
	runtime.EBSVolumes = runAWS("ec2", "describe-volumes", "--output", "json")
	runtime.CloudTrails = runAWS("cloudtrail", "describe-trails", "--output", "json")
	runtime.VPCFlowLogs = runAWS("ec2", "describe-flow-logs", "--output", "json")
	runtime.EKSClusters = runAWS("eks", "list-clusters", "--output", "json")

	if runtime.AccountID == "" {
		runtime.CollectionErrors = appendUniqueError(runtime.CollectionErrors, "failed to resolve AWS account id from sts get-caller-identity")
	}

	fmt.Println("[OK] AWS runtime collection complete")
	fmt.Println()

	return runtime
}

func detectAWSResources(runtime AWSRuntimeData) map[string]AWSResource {
	resources := map[string]AWSResource{
		"iam": {
			Name:      "IAM",
			Available: !isEmptyAWSOutput(runtime.IAMUsers),
			Summary:   summarizeCount(runtime.IAMUsers, "Users"),
		},
		"ec2": {
			Name:      "EC2",
			Available: !isEmptyAWSOutput(runtime.SecurityGroups) || !isEmptyAWSOutput(runtime.KeyPairs),
			Summary:   summarizeCount(runtime.SecurityGroups, "SecurityGroups"),
		},
		"s3": {
			Name:      "S3",
			Available: !isEmptyAWSOutput(runtime.S3Buckets),
			Summary:   summarizeCount(runtime.S3Buckets, "Buckets"),
		},
		"rds": {
			Name:      "RDS",
			Available: !isEmptyAWSOutput(runtime.RDSInstances),
			Summary:   summarizeCount(runtime.RDSInstances, "DBInstances"),
		},
		"eks": {
			Name:      "EKS",
			Available: !isEmptyAWSOutput(runtime.EKSClusters),
			Summary:   summarizeCount(runtime.EKSClusters, "clusters"),
		},
		"elb": {
			Name:      "ELB",
			Available: !isEmptyAWSOutput(runtime.LoadBalancers),
			Summary:   summarizeCount(runtime.LoadBalancers, "LoadBalancers"),
		},
		"cloudtrail": {
			Name:      "CloudTrail",
			Available: !isEmptyAWSOutput(runtime.CloudTrails),
			Summary:   summarizeCount(runtime.CloudTrails, "trailList"),
		},
		"vpc": {
			Name:      "VPC",
			Available: !isEmptyAWSOutput(runtime.VPCFlowLogs) || !isEmptyAWSOutput(runtime.NetworkACLs),
			Summary:   summarizeCount(runtime.VPCFlowLogs, "FlowLogs"),
		},
	}

	fmt.Println("================================")
	fmt.Println("[*] Detecting AWS resources...")
	fmt.Println("================================")

	for key, resource := range resources {
		fmt.Println("--------------------------------")
		fmt.Println("KEY:", key)
		fmt.Println("NAME:", resource.Name)
		fmt.Println("AVAILABLE:", resource.Available)
		fmt.Println("SUMMARY:", resource.Summary)
		fmt.Println()
		resources[key] = resource
	}

	fmt.Println("================================")
	fmt.Println("[OK] AWS resource detection complete")
	fmt.Println("================================")

	return resources
}

func extractJSONField(raw, field string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return ""
	}

	value, ok := data[field]
	if !ok {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func summarizeCount(raw, field string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "not_collected"
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return "collected"
	}

	value, ok := data[field]
	if !ok {
		return "collected"
	}

	switch typed := value.(type) {
	case []any:
		return fmt.Sprintf("count=%d", len(typed))
	default:
		return "collected"
	}
}
