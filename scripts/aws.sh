#!/bin/bash
# AWS Vulnerability Manual Inspection Script
# Maps to SK Shieldus 2024 Cloud Security Guide (AWS)

OUTPUT_FILE="aws_security_inspection_$(date +%Y%m%d_%H%M%S).txt"

echo "Running AWS inspection... All output will be saved to $OUTPUT_FILE"

{
  echo "========================================================="
  echo "  I. Identity and Access Management (Account Management) "
  echo "========================================================="

  echo -e "\n[1.1 - 1.4] IAM User & Group Management"
  echo "-> Listing all IAM users and groups..."
  aws iam list-users --query 'Users[*].[UserName, CreateDate]' --output table
  aws iam list-groups --query 'Groups[*].[GroupName]' --output table

  echo -e "\n[1.8] Admin Console Access Key Lifecycle"
  echo "-> Fetching the IAM credential report (Ensure it is generated first using 'aws iam generate-credential-report')"
  aws iam get-credential-report --query 'Content' --output text | base64 --decode | cut -d, -f1,4,5,9,10,11,14,15,16 | head -n 10

  echo -e "\n[1.10] AWS Account Password Policy"
  echo "-> Fetching IAM password policy..."
  aws iam get-account-password-policy

  echo -e "\n[1.5 - 1.6] Key Pair Management"
  echo "-> Listing EC2 Key Pairs..."
  aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName, KeyType, CreateTime]' --output table


  echo -e "\n========================================================="
  echo "  III. Virtual Resource Management (Network & Storage)   "
  echo "========================================================="

  echo -e "\n[3.1 - 3.2] Security Group Rules (Inbound/Outbound)"
  echo "-> Fetching Security Groups and their rules..."
  aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName, IpPermissions, IpPermissionsEgress]' --output json

  echo -e "\n[3.3] Network ACL Rules"
  echo "-> Fetching Network ACLs..."
  aws ec2 describe-network-acls --query 'NetworkAcls[*].[NetworkAclId, VpcId, Entries]' --output json

  echo -e "\n[3.4] Routing Table Policies"
  echo "-> Fetching Route Tables..."
  aws ec2 describe-route-tables --query 'RouteTables[*].[RouteTableId, VpcId, Routes]' --output json

  echo -e "\n[3.5 - 3.6] Internet & NAT Gateway Connections"
  echo "-> Listing IGWs and NAT Gateways..."
  aws ec2 describe-internet-gateways --query 'InternetGateways[*].[InternetGatewayId, Attachments]' --output table
  aws ec2 describe-nat-gateways --query 'NatGateways[*].[NatGatewayId, VpcId, State]' --output table

  echo -e "\n[3.7] S3 Bucket Public Access Block & ACLs"
  echo "-> Listing S3 buckets..."
  aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read bucket; do
    echo "Bucket: $bucket"
    echo "  PublicAccessBlock:"
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "  No PublicAccessBlock configuration"
    echo "  ACLs:"
    aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[*].Grantee' --output json
  done

  echo -e "\n[3.8] RDS Subnet Availability Zones"
  echo "-> Fetching RDS Subnet Groups..."
  aws rds describe-db-subnet-groups --query 'DBSubnetGroups[*].[DBSubnetGroupName, Subnets[*].SubnetAvailabilityZone.Name]' --output json

  echo -e "\n[3.10] ELB Connection Management"
  echo "-> Listing Load Balancers..."
  aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerName, Scheme, Type, AvailabilityZones[*].ZoneName]' --output json


  echo -e "\n========================================================="
  echo "  IV. Operations Management (Encryption & Logging)       "
  echo "========================================================="

  echo -e "\n[4.1] EBS Volume Encryption"
  echo "-> Checking default EBS encryption and specific volumes..."
  aws ec2 get-ebs-encryption-by-default
  aws ec2 describe-volumes --query 'Volumes[*].[VolumeId, Encrypted, KmsKeyId]' --output table

  echo -e "\n[4.2] RDS Encryption Settings"
  echo "-> Fetching RDS instances encryption status..."
  aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier, StorageEncrypted, KmsKeyId]' --output table

  echo -e "\n[4.5 - 4.7] CloudTrail & Logging Configuration"
  echo "-> Fetching CloudTrail trail configurations..."
  aws cloudtrail describe-trails --query 'trailList[*].[Name, S3BucketName, KmsKeyId, LogFileValidationEnabled]' --output table

  echo -e "\n[4.11] VPC Flow Logs"
  echo "-> Fetching VPC Flow Logs..."
  aws ec2 describe-flow-logs --query 'FlowLogs[*].[FlowLogId, ResourceId, LogDestinationType, LogDestination]' --output table

  echo -e "\n[4.14 - 4.15] EKS Control Plane Logging & Encryption"
  echo "-> Listing EKS Clusters..."
  aws eks list-clusters --query 'clusters' --output text | tr '\t' '\n' | while read cluster; do
    echo "EKS Cluster: $cluster"
    aws eks describe-cluster --name "$cluster" --query 'cluster.[logging.clusterLogging, encryptionConfig]' --output json
  done

} > "$OUTPUT_FILE" 2>&1

echo "Extraction Complete! You can now review the '$OUTPUT_FILE' file."
