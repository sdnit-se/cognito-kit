terraform {
  required_version = ">= 1.8"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.13 fixed managed login branding with several app clients (#44188).
      version = ">= 6.13, < 7.0"
    }
  }
}
