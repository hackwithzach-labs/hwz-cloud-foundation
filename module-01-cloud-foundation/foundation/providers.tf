###############################################################################
# providers.tf
# Commit this. It is settings, not secrets. Credentials come from your AWS CLI
# profile or environment, never from a file in this repo.
###############################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
      Course      = "hwz-cloud-ai-security-engineer"
    }
  }
}

# Used to build correct ARNs and bucket policies without hardcoding the account.
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
