Create the user pool, its managed login and its app clients with the
OpenTofu module in this crate's repository.

The module lives in
[`opentofu/`](https://github.com/sdnit-se/cognito-kit/tree/main/opentofu).
It needs OpenTofu 1.8 or later and the AWS provider 6.13 or later, below 7.
Pin it to the release that matches the crate:

```hcl
module "cognito" {
  source = "github.com/sdnit-se/cognito-kit//opentofu?ref=v0.3.0"

  name   = "portal"
  domain = { name = "login.example.com", certificate_arn = var.certificate_arn }
  google = { client_id = var.google_client_id }

  resource_server = {
    identifier = "https://portal.example.com/mcp"
    scopes     = { drafts = "Create and edit drafts" }
  }

  clients = {
    web = {
      confidential       = true
      callback_urls      = ["https://portal.example.com/callback"]
      logout_urls        = ["https://portal.example.com/"]
      identity_providers = ["Google"]
      scopes             = ["openid", "email", "profile"]
    }
    claude = {
      callback_urls      = ["https://claude.ai/api/mcp/auth_callback"]
      identity_providers = ["Google"]
      scopes             = ["openid", "email", "https://portal.example.com/mcp/drafts"]
    }
  }

  registration = { template_client = "claude" }
}
```

[`opentofu/examples/mcp-portal`](https://github.com/sdnit-se/cognito-kit/blob/main/opentofu/examples/mcp-portal/main.tf)
is a complete pool for a web portal with an MCP server, with app clients
for Claude, ChatGPT, Executor and command-line assistants.

# What it creates

- A user pool on the Essentials tier, where people sign in with their email
  address. Deletion protection is on by default. Only administrators create
  users unless you set `invite_only = false`. People who sign in through
  Google are still created at their first sign-in.
- Managed login (version 2) on a prefix domain, or on your own domain with
  an ACM certificate in `us-east-1`.
- Google as an identity provider, if you set `google`.
- A resource server with its scopes, if you set `resource_server`. A token
  carries each scope as `<identifier>/<name>`.
- One app client per entry in `clients`, with managed login branding for
  each.
- With `registration`, a DynamoDB table for
  [`DynamoStore`](crate::registration::DynamoStore) and an IAM policy for
  the server that runs the [`Registrar`](crate::registration::Registrar).

# How the app clients are set up

Every app client uses the authorization code grant, revokes tokens on
request, and rotates refresh tokens, so a reused refresh token gets
`invalid_grant`. The module refuses `ALLOW_REFRESH_TOKEN_AUTH` in
`explicit_auth_flows`, because that flow turns rotation off.

By default, access and ID tokens last 60 minutes and refresh tokens 30
days. Each client can change that with `access_token_minutes`,
`id_token_minutes` and `refresh_token_days`. `refresh_grace_seconds`, from 0
to 60, lets a client reuse a refresh token briefly, for clients that retry
a refresh.

A client is public unless you set `confidential = true`. Use a confidential
client for a server-side web app, and public ones for assistants.

# Keep the Google secret out of your configuration

The module writes Google's client secret once, as a placeholder unless you
pass `client_secret`, and never changes it afterwards. Set the real secret
in the Cognito console or with the AWS CLI, so it never enters a
configuration file.

It still reaches your state. OpenTofu reads the identity provider back on
every refresh, and Cognito returns the secret with it, so the state and any
saved plan hold it. Keep both where secrets may live: an encrypted backend
with tight access, or OpenTofu's state encryption.

# Wire the outputs to the crate

| Output | Use it for |
|--------|------------|
| `pool_id` | [`PoolId`](crate::PoolId), for [`UserPool::new`](crate::UserPool::new) |
| `login_domain` | [`LoginDomain`](crate::LoginDomain), for managed login and the OAuth front |
| `client_ids` | [`ClientId`](crate::ClientId) of each app client, by name |
| `client_secrets` | [`ClientSecret`](crate::ClientSecret) of each confidential client (sensitive) |
| `resource_scopes` | [`Scope`](crate::Scope) values, as tokens carry them |
| `issuer` | The `iss` of every token, if you need it elsewhere |
| `registration_table` | The table name for [`DynamoStore::new`](crate::registration::DynamoStore::new) |
| `registration_template_client_id` | The template for [`CognitoApi::new`](crate::registration::CognitoApi::new) |
| `registration_policy_json` | An IAM policy to attach to the server's role |

The policy allows the registrar's calls on this pool's app clients and on
this table, and nothing else.

App clients that the registrar creates count toward the pool's quota of
1,000, as do the module's. Once the pool is full, an apply that adds an app
client fails. The registrar stops at
[`max_registrations`](crate::registration::RegistrarBuilder::max_registrations),
500 by default, to leave room for yours.
