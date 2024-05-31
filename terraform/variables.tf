variable "private_subnet_cidrs" {
  default = [
    "10.0.3.0/24",
    "10.0.4.0/24"
  ]
}

variable "public_subnet_cidrs" {
  default = [
    "10.0.1.0/24",
    "10.0.2.0/24"
  ]
}

variable "aws_account_id" {
  default = "AWS_ACCOUNT_ID"
}

variable "aws_managed_key_id_secrets_manager" {
  default = "AWS_MANAGED_KEY_ID"
}

variable "region" {
  default = "us-east-1"
}

variable "secret" {
  default = "python-weather-app/api-key-######"
}

variable "tf_state_bucket" {
  default = "STATE_BUCKET_NAME"
}

variable "tags" {
  description = "mutual tags for all resources"
  type        = map(any)
  default = {
    Environment = "Production"
    IaC         = "Terraform"
    Application = "Python Weather Application"
    Github_Repo = "ACCOUNT/REPO_NAME"
  }
}