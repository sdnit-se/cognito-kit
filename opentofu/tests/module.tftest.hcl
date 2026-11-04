# What Cognito, an MCP client and an attacker would notice about the planned
# pool. The provider is mocked, so this runs without AWS credentials.

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "eu-north-1" }
  }
}

variables {
  name   = "test"
  domain = { prefix = "cognito-kit-test" }
  resource_server = {
    identifier = "https://portal.example.com/mcp"
    scopes     = { drafts = "Create and edit drafts" }
  }
  clients = {
    web = {
      confidential       = true
      callback_urls      = ["https://portal.example.com/auth/callback"]
      identity_providers = ["COGNITO"]
      scopes             = ["openid", "email"]
    }
    claude = {
      callback_urls      = ["https://claude.ai/api/mcp/auth_callback"]
      identity_providers = ["Google"]
      scopes             = ["openid", "https://portal.example.com/mcp/drafts"]
    }
  }
  google = { client_id = "example.apps.googleusercontent.com" }
}

run "every_client_rotates_refresh_tokens" {
  command = plan

  assert {
    condition     = alltrue([for c in aws_cognito_user_pool_client.this : c.refresh_token_rotation[0].feature == "ENABLED"])
    error_message = "A client without rotation lets a stolen refresh token live for its whole validity."
  }

  assert {
    condition     = alltrue([for c in aws_cognito_user_pool_client.this : !contains(c.explicit_auth_flows, "ALLOW_REFRESH_TOKEN_AUTH")])
    error_message = "Cognito rotates only when ALLOW_REFRESH_TOKEN_AUTH is off."
  }
}

run "assistants_are_public_clients_on_the_code_grant" {
  command = plan

  assert {
    condition     = aws_cognito_user_pool_client.this["claude"].generate_secret == false && aws_cognito_user_pool_client.this["web"].generate_secret == true
    error_message = "MCP clients authenticate with PKCE alone (token_endpoint_auth_methods_supported is none)."
  }

  assert {
    condition     = alltrue([for c in aws_cognito_user_pool_client.this : c.allowed_oauth_flows == toset(["code"])])
    error_message = "Only the authorization code grant; never implicit."
  }
}

run "managed_login_is_version_2_and_branded_per_client" {
  command = plan

  assert {
    condition     = aws_cognito_user_pool_domain.this.managed_login_version == 2
    error_message = "Branding needs managed login v2."
  }

  assert {
    condition     = length(aws_cognito_managed_login_branding.this) == 2
    error_message = "Each app client has its own branding style."
  }
}

run "refuses_the_refresh_token_auth_flow" {
  command = plan

  variables {
    clients = {
      legacy = {
        callback_urls       = ["https://app.example.com/callback"]
        identity_providers  = ["COGNITO"]
        scopes              = ["openid"]
        explicit_auth_flows = ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]
      }
    }
  }

  expect_failures = [var.clients]
}

run "refuses_an_ambiguous_domain" {
  command = plan

  variables {
    domain = { prefix = "cognito-kit-test", name = "login.example.com" }
  }

  expect_failures = [var.domain]
}

run "registration_reaches_only_its_pool_and_table" {
  command = apply

  variables {
    registration = { template_client = "claude" }
  }

  assert {
    condition     = aws_dynamodb_table.registrations[0].hash_key == "pk" && aws_dynamodb_table.registrations[0].billing_mode == "PAY_PER_REQUEST"
    error_message = "DynamoStore keys items by a string pk."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(output.registration_policy_json).Statement :
      alltrue([for resource in statement.Resource : contains([aws_cognito_user_pool.this.arn, aws_dynamodb_table.registrations[0].arn], resource)])
    ])
    error_message = "The server may change app clients in its own pool and items in its own table, nowhere else."
  }

  assert {
    condition     = output.registration_template_client_id == aws_cognito_user_pool_client.this["claude"].id
    error_message = "Registered clients copy the template client."
  }
}

run "the_registrations_table_name_suits_dynamodb_whatever_the_pool_is_called" {
  command = plan

  variables {
    name         = "Portal + docs"
    registration = { template_client = "claude" }
  }

  assert {
    condition     = can(regex("^[a-zA-Z0-9_.-]{3,255}$", aws_dynamodb_table.registrations[0].name))
    error_message = "DynamoDB refuses a table name with a space or a plus."
  }
}

run "registration_needs_a_template_from_the_clients" {
  command = plan

  variables {
    registration = { template_client = "missing" }
  }

  expect_failures = [var.registration]
}
