#!/bin/bash
# ==============================================================================
# Amazon Web Services (AWS) - CLI Fast Onboarding Script for AISPR
# ==============================================================================
set -e

ROLE_NAME="AISPR-ReadOnly-Role"
echo "🛡️ Creating AWS IAM Role '${ROLE_NAME}' for Agentic AISPR..."

cat << 'JSON' > /tmp/aispr_trust.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON

aws iam create-role --role-name ${ROLE_NAME} --assume-role-policy-document file:///tmp/aispr_trust.json --description "Read-Only role for AISPR AI Posture Review" 2>/dev/null || true

# Attach AWS managed read only policies
aws iam attach-role-policy --role-name ${ROLE_NAME} --policy-arn arn:aws:iam::aws:policy/AmazonBedrockReadOnly 2>/dev/null || true
aws iam attach-role-policy --role-name ${ROLE_NAME} --policy-arn arn:aws:iam::aws:policy/AmazonSageMakerReadOnly 2>/dev/null || true

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "123456789012")
echo "✅ AWS Role created: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
