#!/usr/bin/env bash
# A live run of client registration against a throwaway user pool and
# DynamoDB table, both named cognito-kit-it-<random> and tagged
# purpose=cognito-kit-it. Deletes both on exit, whatever happens.
#
#   AWS_PROFILE=... AWS_REGION=eu-north-1 PLAYWRIGHT=<playwright's index.mjs> tests/live/registration.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
name="cognito-kit-it-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
domain="ck-it-${name#cognito-kit-it-}"
work="$(mktemp -d)"
chmod 700 "$work"
base="http://127.0.0.1:3000"
mcp="$base/mcp"
pool=""
server=""

cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null || true
  if [ -n "$pool" ]; then
    aws cognito-idp delete-user-pool-domain --user-pool-id "$pool" --domain "$domain" >/dev/null 2>&1 || true
    aws cognito-idp delete-user-pool --user-pool-id "$pool" >/dev/null && echo "deleted pool $name"
  fi
  if aws dynamodb describe-table --table-name "$name" >/dev/null 2>&1; then
    aws dynamodb delete-table --table-name "$name" >/dev/null && aws dynamodb wait table-not-exists --table-name "$name" && echo "deleted table $name"
  fi
  echo "pools named $name: $(aws cognito-idp list-user-pools --max-results 60 --query "length(UserPools[?Name=='$name'])")"
  echo "tables named $name: $(aws dynamodb list-tables --query "length(TableNames[?@=='$name'])")"
  rm -rf "$work"
}
trap cleanup EXIT

echo "creating $name"
pool=$(aws cognito-idp create-user-pool --pool-name "$name" --user-pool-tier ESSENTIALS \
  --user-pool-tags purpose=cognito-kit-it --username-attributes email --auto-verified-attributes email \
  --admin-create-user-config AllowAdminCreateUserOnly=true --query UserPool.Id --output text)
aws cognito-idp create-user-pool-domain --user-pool-id "$pool" --domain "$domain" --managed-login-version 2 >/dev/null
aws cognito-idp create-resource-server --user-pool-id "$pool" --identifier "$mcp" --name mcp \
  --scopes ScopeName=drafts,ScopeDescription=drafts >/dev/null
template=$(aws cognito-idp create-user-pool-client --user-pool-id "$pool" --client-name template --no-generate-secret \
  --allowed-o-auth-flows-user-pool-client --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email "$mcp/drafts" --supported-identity-providers COGNITO \
  --callback-urls https://template.invalid/callback --explicit-auth-flows ALLOW_USER_AUTH ALLOW_USER_SRP_AUTH \
  --refresh-token-rotation Feature=ENABLED,RetryGracePeriodSeconds=0 --enable-token-revocation \
  --prevent-user-existence-errors ENABLED --query UserPoolClient.ClientId --output text)
# A style of its own, so that copying it copies settings rather than Cognito's defaults.
style=$(aws cognito-idp create-managed-login-branding --user-pool-id "$pool" --client-id "$template" \
  --use-cognito-provided-values --query ManagedLoginBranding.ManagedLoginBrandingId --output text)
aws cognito-idp describe-managed-login-branding --user-pool-id "$pool" --managed-login-branding-id "$style" \
  --return-merged-resources --query ManagedLoginBranding.Settings > "$work/settings.json"
aws cognito-idp update-managed-login-branding --user-pool-id "$pool" --managed-login-branding-id "$style" \
  --no-use-cognito-provided-values --settings "file://$work/settings.json" >/dev/null

password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')Aa1!"
printf '{"email":"live@cognito-kit.invalid","password":"%s"}' "$password" > "$work/user.json"
chmod 600 "$work/user.json"
aws cognito-idp admin-create-user --user-pool-id "$pool" --username live@cognito-kit.invalid \
  --message-action SUPPRESS --user-attributes Name=email,Value=live@cognito-kit.invalid Name=email_verified,Value=true >/dev/null
aws cognito-idp admin-set-user-password --user-pool-id "$pool" --username live@cognito-kit.invalid \
  --password "$password" --permanent

aws dynamodb create-table --table-name "$name" --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=pk,AttributeType=S --key-schema AttributeName=pk,KeyType=HASH \
  --tags Key=purpose,Value=cognito-kit-it >/dev/null
aws dynamodb wait table-exists --table-name "$name"

(cd tests/live/server && CARGO_TARGET_DIR=../../../target/live cargo build -q)
COGNITO_POOL_ID="$pool" COGNITO_LOGIN_DOMAIN="https://$domain.auth.${AWS_REGION}.amazoncognito.com" \
  TEMPLATE_CLIENT_ID="$template" REGISTRATION_TABLE="$name" PUBLIC_URL="$base" \
  CLIENT_HOSTS=claude.ai,chatgpt.com,executor.sh IDLE_AFTER_SECONDS=0 \
  target/live/debug/cognito-kit-live > "$work/server.log" 2>&1 &
server=$!
for _ in $(seq 50); do curl -s -o /dev/null "$base/.well-known/oauth-authorization-server" && break; sleep 0.2; done

# A failed flow or cleanup fails the run, after the checks below.
status=0
BASE="$base" USER_FILE="$work/user.json" COGNITO_POOL_ID="$pool" REGISTRATION_TABLE="$name" \
  bun tests/live/registration.ts || status=$?

echo "app clients after the run:"
aws cognito-idp list-user-pool-clients --user-pool-id "$pool" --max-results 60 \
  --query 'UserPoolClients[].[ClientName]' --output text | sort
for client in $(aws cognito-idp list-user-pool-clients --user-pool-id "$pool" --max-results 60 \
  --query "UserPoolClients[?ClientName!='template'].ClientId" --output text); do
  aws cognito-idp describe-user-pool-client --user-pool-id "$pool" --client-id "$client" \
    --query 'UserPoolClient.{name:ClientName,callbacks:CallbackURLs,secret:ClientSecret!=null,rotation:RefreshTokenRotation.Feature,scopes:AllowedOAuthScopes}' --output json
  aws cognito-idp describe-managed-login-branding-by-client --user-pool-id "$pool" --client-id "$client" \
    --query '{style_copied:ManagedLoginBranding.UseCognitoProvidedValues==`false`}' --output json
done
echo "registration items: $(aws dynamodb scan --table-name "$name" --select COUNT --query Count)"
cleaned=$(curl -sS --fail-with-body -X POST "$base/cleanup") || status=1
echo "cleanup: $cleaned"
echo "app clients after cleanup: $(aws cognito-idp list-user-pool-clients --user-pool-id "$pool" --max-results 60 --query 'UserPoolClients[].ClientName' --output text)"
echo "registration items after cleanup: $(aws dynamodb scan --table-name "$name" --select COUNT --query Count)"
echo "server log:"; tail -5 "$work/server.log"
exit "$status"
