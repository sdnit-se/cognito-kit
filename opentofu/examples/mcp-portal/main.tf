# A pool for a web portal with an MCP server at https://portal.example.com/mcp.
# Staff sign in with Google; each AI assistant has its own public app client.

terraform {
  required_version = ">= 1.8"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.13, < 7.0" }
  }
}

provider "aws" {
  region = "eu-north-1"
}

variable "google_client_id" {
  type = string
}

variable "certificate_arn" {
  description = "An ACM certificate in us-east-1 for login.example.com."
  type        = string
}

locals {
  mcp    = "https://portal.example.com/mcp"
  drafts = "${local.mcp}/drafts"
  assistant = {
    identity_providers = ["Google"]
    scopes             = ["openid", "email", "profile", local.drafts]
  }
}

module "cognito" {
  source = "../.."

  name   = "portal"
  domain = { name = "login.example.com", certificate_arn = var.certificate_arn }
  # The secret is set out of band, so it never enters a file or the plan.
  google = { client_id = var.google_client_id }

  resource_server = {
    identifier = local.mcp
    name       = "Portal MCP"
    scopes     = { drafts = "Create and edit drafts" }
  }

  clients = {
    web = {
      confidential       = true
      callback_urls      = ["https://portal.example.com/auth/callback"]
      logout_urls        = ["https://portal.example.com/"]
      identity_providers = ["Google"]
      scopes             = ["openid", "email", "profile"]
    }
    claude = merge(local.assistant, {
      callback_urls = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]
    })
    # The URL ChatGPT shows when the connector is created.
    chatgpt = merge(local.assistant, {
      callback_urls = ["https://chatgpt.com/connector/oauth/example"]
    })
    executor = merge(local.assistant, {
      callback_urls = ["http://127.0.0.1:4312/api/oauth/callback", "http://localhost:4312/api/oauth/callback"]
    })
    # Claude Code (--callback-port 8765) and Codex (mcp_oauth_callback_port = 8765).
    cli = merge(local.assistant, {
      callback_urls = ["http://localhost:8765/callback", "http://127.0.0.1:8765/callback"]
    })
  }
}

output "pool_id" {
  value = module.cognito.pool_id
}

output "client_ids" {
  value = module.cognito.client_ids
}
