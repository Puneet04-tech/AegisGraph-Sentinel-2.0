# AegisGraph Sentinel Enterprise - Main Terraform Configuration
# Multi-cloud Infrastructure as Code

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    azure  = { source = "hashicorp/azurerm", version = "~> 3.0" }
    google = { source = "hashicorp/google", version = "~> 5.0" }
    helm   = { source = "hashicorp/helm", version = "~> 2.0" }
    kubectl = { source = "gavinbunney/kubectl", version = "~> 1.0" }
  }

  backend "s3" {
    bucket = "aegisgraph-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  sensitive   = true
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = string
  sensitive   = true
}

variable "gcp_project" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "cluster_name" {
  description = "Kubernetes cluster name"
  type        = string
  default     = "aegisgraph-sentinel"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "instance_type" {
  description = "Instance type for worker nodes"
  type        = string
  default     = "m5.xlarge"
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

variable "redis_password" {
  description = "Redis password"
  type        = string
  sensitive   = true
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "aegisgraph.com"
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  type        = string
  default     = ""
}

# Local values for common calculations
locals {
  common_tags = {
    Project     = "AegisGraph Sentinel"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Version     = "2.0"
  }

  kubernetes_version = "1.28"
  monitoring_stack  = {
    prometheus   = true
    grafana      = true
    alertmanager = true
    elasticsearch = true
  }
}

# Get available availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

output "aws_availability_zones" {
  value = data.aws_availability_zones.available.names
}

output "cluster_endpoint" {
  description = "Kubernetes cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "Kubernetes cluster name"
  value       = module.eks.cluster_name
}