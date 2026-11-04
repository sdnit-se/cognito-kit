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

output "registration_table" {
  description = "The Registrar's DynamoDB table, for cognito-kit's DynamoStore."
  value       = try(aws_dynamodb_table.registrations[0].name, null)
}

output "registration_template_client_id" {
  description = "The app client registered clients are made like, for cognito-kit's CognitoApi."
  value       = var.registration == null ? null : aws_cognito_user_pool_client.this[var.registration.template_client].id
}

output "registration_policy_json" {
  description = "An IAM policy for the server that runs the Registrar: app clients in this pool, and its table."
  value       = local.registration_policy
}
