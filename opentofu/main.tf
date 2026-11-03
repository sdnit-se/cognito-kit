data "aws_region" "current" {}

locals {
  login_domain = var.domain.name != null ? "https://${var.domain.name}" : "https://${var.domain.prefix}.auth.${data.aws_region.current.region}.amazoncognito.com"
  issuer       = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

resource "aws_cognito_user_pool" "this" {
  name                     = var.name
  user_pool_tier           = "ESSENTIALS"
  deletion_protection      = var.deletion_protection ? "ACTIVE" : "INACTIVE"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  tags                     = var.tags

  admin_create_user_config {
    allow_admin_create_user_only = var.invite_only
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  sign_in_policy {
    allowed_first_auth_factors = var.sign_in_factors
  }
}

resource "aws_cognito_user_pool_domain" "this" {
  user_pool_id          = aws_cognito_user_pool.this.id
  domain                = coalesce(var.domain.name, var.domain.prefix)
  certificate_arn       = var.domain.certificate_arn
  managed_login_version = 2
}

resource "aws_cognito_identity_provider" "google" {
  count = var.google == null ? 0 : 1

  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = var.google.client_id
    client_secret    = coalesce(var.google.client_secret, "set-out-of-band")
    authorize_scopes = join(" ", var.google.scopes)
  }

  attribute_mapping = {
    email          = "email"
    email_verified = "email_verified"
    name           = "name"
    username       = "sub"
  }

  lifecycle {
    ignore_changes = [provider_details["client_secret"]]
  }
}

resource "aws_cognito_resource_server" "this" {
  count = var.resource_server == null ? 0 : 1

  user_pool_id = aws_cognito_user_pool.this.id
  identifier   = var.resource_server.identifier
  name         = coalesce(var.resource_server.name, var.resource_server.identifier)

  dynamic "scope" {
    for_each = var.resource_server.scopes
    content {
      scope_name        = scope.key
      scope_description = scope.value
    }
  }
}

resource "aws_cognito_user_pool_client" "this" {
  for_each = var.clients

  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = each.value.scopes
  callback_urls                        = each.value.callback_urls
  logout_urls                          = each.value.logout_urls
  supported_identity_providers         = each.value.identity_providers
  generate_secret                      = each.value.confidential
  explicit_auth_flows                  = each.value.explicit_auth_flows
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true

  access_token_validity  = each.value.access_token_minutes
  id_token_validity      = each.value.id_token_minutes
  refresh_token_validity = each.value.refresh_token_days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  # A reused refresh token gets invalid_grant. MCP requires rotation for
  # public clients.
  refresh_token_rotation {
    feature                    = "ENABLED"
    retry_grace_period_seconds = each.value.refresh_grace_seconds
  }

  # Scopes and providers must exist before a client can name them.
  depends_on = [aws_cognito_resource_server.this, aws_cognito_identity_provider.google]
}

resource "aws_cognito_managed_login_branding" "this" {
  for_each = var.clients

  user_pool_id = aws_cognito_user_pool.this.id
  client_id    = aws_cognito_user_pool_client.this[each.key].id

  use_cognito_provided_values = var.branding == null || try(var.branding.settings, null) == null
  settings                    = try(var.branding.settings, null)

  dynamic "asset" {
    for_each = var.branding == null ? [] : var.branding.assets
    content {
      category   = asset.value.category
      color_mode = asset.value.color_mode
      extension  = asset.value.extension
      bytes      = filebase64(asset.value.path)
    }
  }

  depends_on = [aws_cognito_user_pool_domain.this]
}
