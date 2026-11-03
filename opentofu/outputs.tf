output "pool_id" {
  description = "The user pool id, for cognito-kit's PoolId."
  value       = aws_cognito_user_pool.this.id
}

output "pool_arn" {
  value = aws_cognito_user_pool.this.arn
}

output "issuer" {
  description = "The iss of every token the pool issues."
  value       = local.issuer
}

output "login_domain" {
  description = "Managed login's origin, for cognito-kit's LoginDomain."
  value       = local.login_domain
}

output "client_ids" {
  description = "App client ids, by client name."
  value       = { for name, client in aws_cognito_user_pool_client.this : name => client.id }
}

output "client_secrets" {
  description = "Secrets of the confidential clients, by client name."
  value       = { for name, client in aws_cognito_user_pool_client.this : name => client.client_secret if var.clients[name].confidential }
  sensitive   = true
}

output "resource_scopes" {
  description = "The resource server's scopes as tokens carry them: <identifier>/<name>."
  value       = try(aws_cognito_resource_server.this[0].scope_identifiers, [])
}
