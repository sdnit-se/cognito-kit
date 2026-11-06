use std::collections::HashMap;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, ReturnValue, TransactWriteItem};

use super::{BoxFuture, Lease, Registration, RegistrationKind, RegistrationStore};
use crate::config::ClientId;
use crate::http_client::BoxError;

type Item = HashMap<String, AttributeValue>;

/// [`RegistrationStore`] in a DynamoDB table whose partition key is a
/// string named `pk`, with no sort key. The OpenTofu module creates one.
///
/// Each registration is an item under `client#<client_id>`, with its lease
/// as `lease_owner` and `lease_until`, and a second item under
/// `app#<app client id>` that points back to it. The caller
/// needs `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem` and `Scan`
/// on the table.
#[derive(Clone)]
pub struct DynamoStore {
    client: Client,
    table: String,
}

impl DynamoStore {
    /// Keeps registrations in `table`.
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    async fn item(&self, pk: String) -> Result<Option<Item>, BoxError> {
        let output = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(pk))
            .consistent_read(true)
            .send()
            .await?;
        Ok(output.item)
    }

    async fn get(&self, client_id: &str) -> Result<Option<Registration>, BoxError> {
        self.item(format!("client#{client_id}"))
            .await?
            .map(|item| registration(&item))
            .transpose()
    }

    async fn get_by_app_client(&self, app_client: &ClientId) -> Result<Option<Registration>, BoxError> {
        let Some(pointer) = self.item(format!("app#{app_client}")).await? else {
            return Ok(None);
        };
        // A pointer left by an interrupted removal names a client id that
        // may since have been registered with another app client.
        let found = self.get(string(&pointer, "client_id")?).await?;
        Ok(found.filter(|r| r.app_client == *app_client))
    }

    async fn insert(&self, registration: Registration) -> Result<Registration, BoxError> {
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item(&registration)))
            .condition_expression("attribute_not_exists(pk)")
            .build()?;
        let pointer = Put::builder()
            .table_name(&self.table)
            .item(
                "pk",
                AttributeValue::S(format!("app#{}", registration.app_client)),
            )
            .item("client_id", AttributeValue::S(registration.client_id.clone()))
            .build()?;
        let written = self
            .client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(put).build())
            .transact_items(TransactWriteItem::builder().put(pointer).build())
            .send()
            .await;
        match written {
            Ok(_) => Ok(registration),
            Err(error) if taken(error.as_service_error()) => self
                .get(&registration.client_id)
                .await?
                .ok_or_else(|| "the registration went away while being stored".into()),
            Err(error) => Err(error.into()),
        }
    }

    async fn lease(
        &self,
        client_id: &str,
        lease: &Lease,
        now: u64,
    ) -> Result<Option<Registration>, BoxError> {
        let leased = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(format!("client#{client_id}")))
            .update_expression("SET lease_owner = :owner, lease_until = :until")
            .condition_expression(
                "attribute_exists(pk) AND (attribute_not_exists(lease_until) OR lease_until <= :now)",
            )
            .expression_attribute_values(":owner", AttributeValue::S(lease.owner.clone()))
            .expression_attribute_values(":until", AttributeValue::N(lease.until.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;
        match leased {
            Ok(output) => output.attributes.map(|item| registration(&item)).transpose(),
            Err(error) if refused(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn update(&self, registration: &Registration, lease: &Lease) -> Result<bool, BoxError> {
        let uris = registration
            .redirect_uris
            .iter()
            .cloned()
            .map(AttributeValue::S)
            .collect();
        let name = registration
            .client_name
            .clone()
            .map_or(AttributeValue::Null(true), AttributeValue::S);
        let updated = self
            .client
            .update_item()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(format!("client#{}", registration.client_id)),
            )
            .update_expression("SET redirect_uris = :uris, client_name = :name, fetched_at = :at")
            .condition_expression("lease_owner = :owner")
            .expression_attribute_values(":owner", AttributeValue::S(lease.owner.clone()))
            .expression_attribute_values(":uris", AttributeValue::L(uris))
            .expression_attribute_values(":name", name)
            .expression_attribute_values(":at", AttributeValue::N(registration.fetched_at.to_string()))
            .send()
            .await;
        match updated {
            Ok(_) => Ok(true),
            Err(error) if refused(&error) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn release(&self, client_id: &str, lease: &Lease) -> Result<(), BoxError> {
        let released = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(format!("client#{client_id}")))
            .update_expression("REMOVE lease_owner, lease_until")
            .condition_expression("lease_owner = :owner")
            .expression_attribute_values(":owner", AttributeValue::S(lease.owner.clone()))
            .send()
            .await;
        ignore_removed(released)
    }

    async fn touch(&self, client_id: &str, at: u64) -> Result<(), BoxError> {
        let updated = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(format!("client#{client_id}")))
            .update_expression("SET last_used = :at")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":at", AttributeValue::N(at.to_string()))
            .send()
            .await;
        ignore_removed(updated)
    }

    async fn remove(&self, registration: &Registration) -> Result<(), BoxError> {
        let app = AttributeValue::S(registration.app_client.to_string());
        let client = Delete::builder()
            .table_name(&self.table)
            .key(
                "pk",
                AttributeValue::S(format!("client#{}", registration.client_id)),
            )
            .condition_expression("attribute_not_exists(pk) OR app_client = :app")
            .expression_attribute_values(":app", app)
            .build()?;
        let pointer_key = AttributeValue::S(format!("app#{}", registration.app_client));
        let pointer = Delete::builder()
            .table_name(&self.table)
            .key("pk", pointer_key.clone())
            .build()?;
        let removed = self
            .client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().delete(client).build())
            .transact_items(TransactWriteItem::builder().delete(pointer).build())
            .send()
            .await;
        match removed {
            Ok(_) => Ok(()),
            // The client id now belongs to another app client: keep its
            // registration and drop only this one's pointer.
            Err(error) if taken(error.as_service_error()) => {
                self.client
                    .delete_item()
                    .table_name(&self.table)
                    .key("pk", pointer_key)
                    .send()
                    .await?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn list(&self) -> Result<Vec<Registration>, BoxError> {
        let mut found = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(&self.table)
                .filter_expression("begins_with(pk, :prefix)")
                .expression_attribute_values(":prefix", AttributeValue::S("client#".into()))
                .consistent_read(true)
                .set_exclusive_start_key(start)
                .send()
                .await?;
            for item in page.items.unwrap_or_default() {
                found.push(registration(&item)?);
            }
            start = page.last_evaluated_key;
            if start.is_none() {
                return Ok(found);
            }
        }
    }
}

/// Whether a transaction failed because the registration exists.
fn taken(error: Option<&TransactWriteItemsError>) -> bool {
    matches!(error, Some(TransactWriteItemsError::TransactionCanceledException(e))
        if e.cancellation_reasons().iter().any(|r| r.code() == Some("ConditionalCheckFailed")))
}

/// Whether a write's condition failed.
fn refused<E: ProvideErrorMetadata>(error: &SdkError<E>) -> bool {
    error.code() == Some("ConditionalCheckFailedException")
}

/// A registration that cleanup removed meanwhile stays removed.
fn ignore_removed<T, E>(result: Result<T, SdkError<E>>) -> Result<(), BoxError>
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    match result {
        Ok(_) => Ok(()),
        Err(error) if refused(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn item(registration: &Registration) -> Item {
    let mut item = Item::new();
    let mut set = |key: &str, value| {
        item.insert(key.to_owned(), value);
    };
    set(
        "pk",
        AttributeValue::S(format!("client#{}", registration.client_id)),
    );
    set("client_id", AttributeValue::S(registration.client_id.clone()));
    set(
        "app_client",
        AttributeValue::S(registration.app_client.to_string()),
    );
    let kind = match registration.kind {
        RegistrationKind::Document => "document",
        RegistrationKind::Dynamic => "dynamic",
    };
    set("kind", AttributeValue::S(kind.to_owned()));
    if let Some(name) = &registration.client_name {
        set("client_name", AttributeValue::S(name.clone()));
    }
    let uris = registration
        .redirect_uris
        .iter()
        .cloned()
        .map(AttributeValue::S)
        .collect();
    set("redirect_uris", AttributeValue::L(uris));
    set(
        "created_at",
        AttributeValue::N(registration.created_at.to_string()),
    );
    if let Some(at) = registration.last_used {
        set("last_used", AttributeValue::N(at.to_string()));
    }
    set(
        "fetched_at",
        AttributeValue::N(registration.fetched_at.to_string()),
    );
    item
}

fn string<'a>(item: &'a Item, key: &str) -> Result<&'a str, BoxError> {
    match item.get(key) {
        Some(AttributeValue::S(s)) => Ok(s),
        _ => Err(format!("the registration item has no string {key}").into()),
    }
}

fn number(item: &Item, key: &str) -> Result<Option<u64>, BoxError> {
    match item.get(key) {
        Some(AttributeValue::N(n)) => Ok(Some(n.parse()?)),
        None | Some(AttributeValue::Null(_)) => Ok(None),
        _ => Err(format!("the registration item's {key} is not a number").into()),
    }
}

fn registration(item: &Item) -> Result<Registration, BoxError> {
    let kind = match string(item, "kind")? {
        "document" => RegistrationKind::Document,
        "dynamic" => RegistrationKind::Dynamic,
        other => return Err(format!("unknown registration kind {other}").into()),
    };
    let redirect_uris = match item.get("redirect_uris") {
        Some(AttributeValue::L(uris)) => uris.iter().filter_map(|u| u.as_s().ok().cloned()).collect(),
        _ => Vec::new(),
    };
    Ok(Registration {
        client_id: string(item, "client_id")?.to_owned(),
        app_client: string(item, "app_client")?.parse()?,
        kind,
        client_name: item.get("client_name").and_then(|n| n.as_s().ok().cloned()),
        redirect_uris,
        created_at: number(item, "created_at")?.unwrap_or_default(),
        last_used: number(item, "last_used")?,
        fetched_at: number(item, "fetched_at")?.unwrap_or_default(),
    })
}

impl RegistrationStore for DynamoStore {
    fn get<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        Box::pin(self.get(client_id))
    }

    fn get_by_app_client<'a>(
        &'a self,
        app_client: &'a ClientId,
    ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        Box::pin(self.get_by_app_client(app_client))
    }

    fn insert(&self, registration: Registration) -> BoxFuture<'_, Result<Registration, BoxError>> {
        Box::pin(self.insert(registration))
    }

    fn lease<'a>(
        &'a self,
        client_id: &'a str,
        lease: &'a Lease,
        now: u64,
    ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        Box::pin(self.lease(client_id, lease, now))
    }

    fn update<'a>(
        &'a self,
        registration: &'a Registration,
        lease: &'a Lease,
    ) -> BoxFuture<'a, Result<bool, BoxError>> {
        Box::pin(self.update(registration, lease))
    }

    fn release<'a>(&'a self, client_id: &'a str, lease: &'a Lease) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(self.release(client_id, lease))
    }

    fn touch<'a>(&'a self, client_id: &'a str, at: u64) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(self.touch(client_id, at))
    }

    fn remove<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(self.remove(registration))
    }

    fn list(&self) -> BoxFuture<'_, Result<Vec<Registration>, BoxError>> {
        Box::pin(self.list())
    }
}
