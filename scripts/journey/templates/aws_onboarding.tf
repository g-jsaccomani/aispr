# ==============================================================================
# Amazon Web Services (AWS) - Zero-Footprint AISPR Read-Only IAM Role Setup
# Target Services: AWS Bedrock • Amazon SageMaker • AWS KMS • S3 AI Buckets
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "trusted_role_arn" {
  type        = string
  default     = "arn:aws:iam::123456789012:root"
  description = "Trusted Principal or AISPR Scanner AWS Identity"
}

# 1. IAM Role with STS AssumeRole Trust
resource "aws_iam_role" "aispr_readonly_role" {
  name        = "AISPR-ReadOnly-Role"
  description = "Read-Only role for Agentic AISPR Multi-Cloud AI-SPM Scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_role_arn
        }
      }
    ]
  })
}

# 2. Granular Read-Only Policy for AI & KMS Resources
resource "aws_iam_policy" "aispr_ai_readonly_policy" {
  name        = "AISPR-AI-Security-Auditor-Policy"
  description = "Least-privilege read-only permissions for AWS Bedrock, SageMaker, S3, and KMS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockReadOnly"
        Effect = "Allow"
        Action = [
          "bedrock:ListFoundationModels",
          "bedrock:GetFoundationModel",
          "bedrock:ListCustomModels",
          "bedrock:GetCustomModel",
          "bedrock:ListModelCustomizationJobs",
          "bedrock:ListGuardrails",
          "bedrock:GetGuardrail",
          "bedrock:ListKnowledgeBases",
          "bedrock:GetKnowledgeBase"
        ]
        Resource = "*"
      },
      {
        Sid    = "SageMakerReadOnly"
        Effect = "Allow"
        Action = [
          "sagemaker:ListEndpoints",
          "sagemaker:DescribeEndpoint",
          "sagemaker:ListModels",
          "sagemaker:DescribeModel",
          "sagemaker:ListNotebookInstances",
          "sagemaker:DescribeNotebookInstance"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityContextReadOnly"
        Effect = "Allow"
        Action = [
          "kms:ListAliases",
          "kms:DescribeKey",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_ai_policy" {
  role       = aws_iam_role.aispr_readonly_role.name
  policy_arn = aws_iam_policy.aispr_ai_readonly_policy.arn
}

output "aws_role_arn" {
  value       = aws_iam_role.aispr_readonly_role.arn
  description = "Share this Role ARN with the AISPR team to enable cross-cloud discovery"
}
