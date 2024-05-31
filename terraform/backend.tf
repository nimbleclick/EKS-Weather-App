terraform {
  # backend "s3" {
  #   bucket         = "STATE_BUCKET_NAME"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "eks-terraform-statelock"
  # }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.38.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "eks_terraform_tfstate_bucket" {
  bucket = var.tf_state_bucket

  tags = merge(var.tags)
}

resource "aws_s3_bucket_versioning" "eks_terraform_tfstate_bucket_versioning" {
  bucket = aws_s3_bucket.eks_terraform_tfstate_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "eks_terraform_tfstate_bucket_server_side_encryption_configuration" {
  bucket = aws_s3_bucket.eks_terraform_tfstate_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_dynamodb_table" "eks_terraform_tfstate_lock" {
  name           = "eks-terraform-statelock"
  billing_mode   = "PROVISIONED"
  hash_key       = "LockID"
  read_capacity  = 5
  write_capacity = 5

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = merge(var.tags)
}