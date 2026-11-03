variable "name" {
  description = "The user pool's name."
  type        = string
}

variable "tags" {
  description = "Tags for the user pool."
  type        = map(string)
  default     = {}
}

variable "deletion_protection" {
  description = "Refuse to delete the pool while it is on."
  type        = bool
  default     = true
}

variable "invite_only" {
  description = "Only administrators create users. Users of a federated provider such as Google are still created at their first sign-in."
  type        = bool
  default     = true
}

variable "sign_in_factors" {
  description = "The first factors managed login offers the pool's own users: PASSWORD, EMAIL_OTP, SMS_OTP or WEB_AUTHN."
  type        = list(string)
  default     = ["PASSWORD"]
}

variable "domain" {
  description = "Managed login's domain: a prefix (<prefix>.auth.<region>.amazoncognito.com), or a custom name with an ACM certificate in us-east-1."
  type = object({
    prefix          = optional(string)
    name            = optional(string)
    certificate_arn = optional(string)
  })

  validation {
    condition     = (var.domain.prefix == null) != (var.domain.name == null)
    error_message = "Set exactly one of domain.prefix and domain.name."
  }

  validation {
    condition     = (var.domain.name == null) == (var.domain.certificate_arn == null)
    error_message = "A custom domain.name needs domain.certificate_arn, and a prefix domain takes none."
  }
}

variable "google" {
  description = "Google as a federated provider. Leave client_secret unset to set it out of band: the module writes a placeholder once and never changes the secret afterwards."
  type = object({
    client_id     = string
    client_secret = optional(string)
    scopes        = optional(list(string), ["openid", "email", "profile"])
  })
  default = null
}

variable "resource_server" {
  description = "A resource server, such as an MCP server, with its identifier (its URL) and scopes (name => description). App clients ask for a scope as \"<identifier>/<name>\"."
  type = object({
    identifier = string
    name       = optional(string)
    scopes     = map(string)
  })
  default = null
}

variable "clients" {
  description = "App clients, by name. Every client uses the authorization code grant, and rotates refresh tokens."
  type = map(object({
    callback_urls      = list(string)
    logout_urls        = optional(list(string), [])
    identity_providers = list(string)
    scopes             = list(string)
    # A confidential client (a server-side web app) gets a secret; assistants and other public clients don't.
    confidential          = optional(bool, false)
    explicit_auth_flows   = optional(list(string), ["ALLOW_USER_AUTH", "ALLOW_USER_SRP_AUTH"])
    access_token_minutes  = optional(number, 60)
    id_token_minutes      = optional(number, 60)
    refresh_token_days    = optional(number, 30)
    refresh_grace_seconds = optional(number, 0)
  }))

  validation {
    condition     = alltrue([for c in var.clients : !contains(c.explicit_auth_flows, "ALLOW_REFRESH_TOKEN_AUTH")])
    error_message = "Refresh-token rotation replaces ALLOW_REFRESH_TOKEN_AUTH; leave it out of explicit_auth_flows."
  }

  validation {
    condition     = alltrue([for c in var.clients : length(setsubtract(c.identity_providers, ["COGNITO", "Google"])) == 0 && length(c.identity_providers) > 0])
    error_message = "identity_providers lists COGNITO (the pool's own users), Google, or both."
  }

  validation {
    condition     = alltrue([for c in var.clients : c.refresh_grace_seconds >= 0 && c.refresh_grace_seconds <= 60])
    error_message = "refresh_grace_seconds is between 0 and 60."
  }
}

variable "branding" {
  description = "Managed login branding for every client: settings JSON from the branding editor or the API, and image assets. Null uses Cognito's own look."
  type = object({
    settings = optional(string)
    assets = optional(list(object({
      category   = string
      color_mode = string
      extension  = string
      path       = string
    })), [])
  })
  default = null
}
