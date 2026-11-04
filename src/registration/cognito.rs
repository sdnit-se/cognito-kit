use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_cognitoidentityprovider::Client;
use aws_sdk_cognitoidentityprovider::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_cognitoidentityprovider::operation::update_user_pool_client::builders::UpdateUserPoolClientFluentBuilder;
use aws_sdk_cognitoidentityprovider::types::{
    ExplicitAuthFlowsType, FeatureType, OAuthFlowType, RefreshTokenRotationType, UserPoolClientType,
};

use super::{AdminError, AppClients, BoxFuture};
use crate::config::{ClientId, PoolId};

/// [`AppClients`] over the AWS SDK. Every app client it creates copies a
/// template app client you manage, such as one made by the OpenTofu module:
/// its scopes, identity providers, token lifetimes and managed login style.
/// Each is public, uses the authorization code grant, and rotates refresh
/// tokens.
///
/// The caller needs `cognito-idp:CreateUserPoolClient`,
/// `UpdateUserPoolClient`, `DeleteUserPoolClient`, `DescribeUserPoolClient`,
/// `ListUserPoolClients`, `CreateManagedLoginBranding` and
/// `DescribeManagedLoginBrandingByClient` on the pool.
#[derive(Clone)]
pub struct CognitoApi {
    client: Client,
    pool: PoolId,
    template: ClientId,
}

impl CognitoApi {
    /// Manages app clients in `pool`, made like `template`.
    pub fn new(client: Client, pool: PoolId, template: ClientId) -> Self {
        Self {
            client,
            pool,
            template,
        }
    }

    async fn describe(&self, client: &ClientId) -> Result<UserPoolClientType, AdminError> {
        let output = self
            .client
            .describe_user_pool_client()
            .user_pool_id(self.pool.as_str())
            .client_id(client.as_str())
            .send()
            .await
            .map_err(admin_error)?;
        output.user_pool_client.ok_or(AdminError::NotFound)
    }

    async fn create_client(&self, name: &str, callback_urls: &[String]) -> Result<ClientId, AdminError> {
        let template = self.describe(&self.template).await?;
        let grace = template
            .refresh_token_rotation
            .as_ref()
            .and_then(|r| r.retry_grace_period_seconds);
        let flows = template
            .explicit_auth_flows
            .unwrap_or_default()
            .into_iter()
            .filter(|f| *f != ExplicitAuthFlowsType::AllowRefreshTokenAuth)
            .collect();
        let created = self
            .client
            .create_user_pool_client()
            .user_pool_id(self.pool.as_str())
            .client_name(name)
            .generate_secret(false)
            .set_refresh_token_validity(Some(template.refresh_token_validity).filter(|v| *v > 0))
            .set_access_token_validity(template.access_token_validity)
            .set_id_token_validity(template.id_token_validity)
            .set_token_validity_units(template.token_validity_units)
            .set_read_attributes(template.read_attributes)
            .set_write_attributes(template.write_attributes)
            .set_explicit_auth_flows(Some(flows))
            .set_supported_identity_providers(template.supported_identity_providers)
            .set_callback_urls(Some(callback_urls.to_vec()))
            .allowed_o_auth_flows(OAuthFlowType::Code)
            .set_allowed_o_auth_scopes(template.allowed_o_auth_scopes)
            .allowed_o_auth_flows_user_pool_client(true)
            .set_prevent_user_existence_errors(template.prevent_user_existence_errors)
            .enable_token_revocation(true)
            .set_auth_session_validity(template.auth_session_validity)
            .refresh_token_rotation(rotation(grace))
            .send()
            .await
            .map_err(admin_error)?;
        let id = created
            .user_pool_client
            .and_then(|c| c.client_id)
            .ok_or_else(|| other("CreateUserPoolClient returned no client id"))?;
        let id: ClientId = id
            .parse()
            .map_err(|_| other("CreateUserPoolClient returned an odd client id"))?;
        // Managed login refuses to show a page for a client without a style.
        if let Err(error) = self.copy_style(&id).await {
            let _ = self.delete_client(&id).await;
            return Err(error);
        }
        Ok(id)
    }

    async fn copy_style(&self, to: &ClientId) -> Result<(), AdminError> {
        let style = self
            .client
            .describe_managed_login_branding_by_client()
            .user_pool_id(self.pool.as_str())
            .client_id(self.template.as_str())
            .send()
            .await;
        let style = match style {
            Ok(output) => output.managed_login_branding,
            Err(error) if error.code() == Some("ResourceNotFoundException") => None,
            Err(error) => return Err(admin_error(error)),
        };
        let request = self
            .client
            .create_managed_login_branding()
            .user_pool_id(self.pool.as_str())
            .client_id(to.as_str());
        let request = match style.filter(|s| !s.use_cognito_provided_values && s.settings.is_some()) {
            Some(style) => request.set_settings(style.settings).set_assets(style.assets),
            None => request.use_cognito_provided_values(true),
        };
        request.send().await.map_err(admin_error)?;
        Ok(())
    }

    async fn delete_client(&self, client: &ClientId) -> Result<(), AdminError> {
        let deleted = self
            .client
            .delete_user_pool_client()
            .user_pool_id(self.pool.as_str())
            .client_id(client.as_str())
            .send()
            .await;
        match deleted.map_err(admin_error) {
            Ok(_) | Err(AdminError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// UpdateUserPoolClient resets every setting it isn't given, so each
    /// one is sent back as it is.
    fn update(&self, current: UserPoolClientType) -> UpdateUserPoolClientFluentBuilder {
        self.client
            .update_user_pool_client()
            .user_pool_id(self.pool.as_str())
            .set_client_id(current.client_id)
            .set_client_name(current.client_name)
            .set_refresh_token_validity(Some(current.refresh_token_validity).filter(|v| *v > 0))
            .set_access_token_validity(current.access_token_validity)
            .set_id_token_validity(current.id_token_validity)
            .set_token_validity_units(current.token_validity_units)
            .set_read_attributes(current.read_attributes)
            .set_write_attributes(current.write_attributes)
            .set_explicit_auth_flows(current.explicit_auth_flows)
            .set_supported_identity_providers(current.supported_identity_providers)
            .set_callback_urls(current.callback_urls)
            .set_logout_urls(current.logout_urls)
            .set_default_redirect_uri(current.default_redirect_uri)
            .set_allowed_o_auth_flows(current.allowed_o_auth_flows)
            .set_allowed_o_auth_scopes(current.allowed_o_auth_scopes)
            .set_allowed_o_auth_flows_user_pool_client(current.allowed_o_auth_flows_user_pool_client)
            .set_analytics_configuration(current.analytics_configuration)
            .set_prevent_user_existence_errors(current.prevent_user_existence_errors)
            .set_enable_token_revocation(current.enable_token_revocation)
            .set_enable_propagate_additional_user_context_data(
                current.enable_propagate_additional_user_context_data,
            )
            .set_auth_session_validity(current.auth_session_validity)
            .set_refresh_token_rotation(current.refresh_token_rotation)
    }

    async fn list_clients(&self, prefix: &str) -> Result<Vec<ClientId>, AdminError> {
        let mut found = Vec::new();
        let mut next = None;
        loop {
            let page = self
                .client
                .list_user_pool_clients()
                .user_pool_id(self.pool.as_str())
                .max_results(60)
                .set_next_token(next)
                .send()
                .await
                .map_err(admin_error)?;
            for client in page.user_pool_clients.unwrap_or_default() {
                let named = client
                    .client_name
                    .as_deref()
                    .is_some_and(|n| n.starts_with(prefix));
                if let Some(id) = client.client_id.filter(|_| named).and_then(|id| id.parse().ok()) {
                    found.push(id);
                }
            }
            next = page.next_token;
            if next.is_none() {
                return Ok(found);
            }
        }
    }
}

fn rotation(grace: Option<i32>) -> RefreshTokenRotationType {
    RefreshTokenRotationType::builder()
        .feature(FeatureType::Enabled)
        .set_retry_grace_period_seconds(grace)
        .build()
        .expect("feature is set")
}

fn other(message: &str) -> AdminError {
    AdminError::Other(Arc::new(message.into()))
}

fn admin_error<E, R>(error: SdkError<E, R>) -> AdminError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug + Send + Sync + 'static,
{
    match error.code() {
        Some("LimitExceededException") => AdminError::Limit,
        Some("ResourceNotFoundException") => AdminError::NotFound,
        _ => AdminError::Other(Arc::new(Box::new(error))),
    }
}

impl AppClients for CognitoApi {
    fn create<'a>(
        &'a self,
        name: &'a str,
        callback_urls: &'a [String],
    ) -> BoxFuture<'a, Result<ClientId, AdminError>> {
        Box::pin(self.create_client(name, callback_urls))
    }

    fn set_callback_urls<'a>(
        &'a self,
        client: &'a ClientId,
        urls: &'a [String],
    ) -> BoxFuture<'a, Result<(), AdminError>> {
        Box::pin(async move {
            let current = self.describe(client).await?;
            self.update(current)
                .set_callback_urls(Some(urls.to_vec()))
                .send()
                .await
                .map_err(admin_error)?;
            Ok(())
        })
    }

    fn delete<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<(), AdminError>> {
        Box::pin(self.delete_client(client))
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<ClientId>, AdminError>> {
        Box::pin(self.list_clients(prefix))
    }

    fn created<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<SystemTime, AdminError>> {
        Box::pin(async move {
            // Without a date, the client counts as new, which keeps it.
            let created = self.describe(client).await?.creation_date;
            Ok(created.map_or_else(SystemTime::now, |d| {
                UNIX_EPOCH + Duration::from_secs(d.secs().max(0) as u64)
            }))
        })
    }
}
