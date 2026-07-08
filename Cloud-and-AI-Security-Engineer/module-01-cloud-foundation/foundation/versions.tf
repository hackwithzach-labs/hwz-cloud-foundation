###############################################################################
# HackWithZach :: Cloud and AI Security Engineer :: Module 1 Foundation
# Provider + version pins. Kept in one place so every pillar inherits the same.
#
# (C) 2026 Vigilantia Technologies INC. All rights reserved.
# "HackWithZach" and the HackWithZach logo are trademarks of Vigilantia Technologies INC.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}
