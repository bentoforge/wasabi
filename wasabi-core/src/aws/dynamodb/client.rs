//! DynamoDB client wrapper with table prefix support.
//!
//! Provides a thin wrapper around the AWS SDK client that automatically
//! applies a table name prefix to all operations, enabling environment-based
//! table isolation (e.g., `prod-users` vs `dev-users`).

use anyhow::Context;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::operation::create_table::builders::CreateTableFluentBuilder;
use aws_sdk_dynamodb::operation::delete_item::builders::DeleteItemFluentBuilder;
use aws_sdk_dynamodb::operation::get_item::builders::GetItemFluentBuilder;
use aws_sdk_dynamodb::operation::put_item::builders::PutItemFluentBuilder;
use aws_sdk_dynamodb::operation::query::builders::QueryFluentBuilder;
use aws_sdk_dynamodb::operation::update_item::builders::UpdateItemFluentBuilder;
use aws_sdk_dynamodb::types::{AttributeValue, TableStatus};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

/// DynamoDB client with automatic table name prefixing.
///
/// All table names passed to this client are automatically prefixed with
/// the value of `DYNAMO_TABLE_PREFIX` environment variable. This allows
/// the same code to work across different environments without changes.
///
/// # Example
///
/// ```rust,ignore
/// let client = DynamoClient::from_env().await?;
///
/// // With DYNAMO_TABLE_PREFIX=myapp-prod, this queries "myapp-prod-users"
/// let result = client.query("users")
///     .key_condition_expression("PK = :pk")
///     .expression_attribute_values(":pk", AttributeValue::S("user#123".into()))
///     .send()
///     .await?;
/// ```
#[derive(Clone, Debug)]
pub struct DynamoClient {
    /// The underlying AWS SDK DynamoDB client.
    pub client: Client,
    table_prefix: String,
}

impl DynamoClient {
    /// Creates a new client from environment configuration.
    ///
    /// Loads AWS credentials from the default credential chain and reads
    /// `DYNAMO_TABLE_PREFIX` from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if `DYNAMO_TABLE_PREFIX` is not set.
    pub async fn from_env() -> anyhow::Result<DynamoClient> {
        tracing::info!("Setting up DynamoDB....");

        // DynamoDB operations are transactional and typically complete in
        // <100ms. Setting tight per-attempt and total timeouts ensures a
        // stuck request cannot cascade into request-handler stalls.
        let timeout_config = aws_config::timeout::TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(3))
            .operation_attempt_timeout(Duration::from_secs(5))
            .operation_timeout(Duration::from_secs(15))
            .build();

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout_config)
            .load()
            .await;
        let client = Client::new(&config);

        let table_prefix = env::var("DYNAMO_TABLE_PREFIX")
            .context("No DYNAMO_TABLE_PREFIX provided in environment")?;

        Ok(DynamoClient {
            client,
            table_prefix,
        })
    }

    /// Returns the effective table name with prefix applied.
    ///
    /// Given logical name `users` and prefix `myapp-prod`, returns `myapp-prod-users`.
    pub fn effective_name(&self, table: &str) -> String {
        format!("{}-{}", self.table_prefix, table)
    }

    /// Checks if a table exists in DynamoDB.
    ///
    /// Returns `true` if the table exists (in any state), `false` if not found.
    pub async fn does_table_exist(&self, name: &str) -> anyhow::Result<bool> {
        let effective_name = self.effective_name(name);

        match self
            .client
            .describe_table()
            .table_name(&effective_name)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .map(|e| e.is_resource_not_found_exception())
                    .unwrap_or(false) =>
            {
                Ok(false)
            }
            Err(e) => Err(e).context(format!("Cannot access DynamoDB table '{}'", effective_name)),
        }
    }

    /// Creates a table if it doesn't already exist.
    ///
    /// The callback receives a [`CreateTableFluentBuilder`] with the table name
    /// already set. Add key schema, attributes, and billing mode in the callback.
    ///
    /// Waits for the table to become `ACTIVE` before returning (up to ~2.5 minutes).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// client.create_table("users", |builder| {
    ///     Ok(builder
    ///         .attribute_definitions(str_attribute("PK")?)
    ///         .key_schema(with_hash_index("PK")?)
    ///         .billing_mode(BillingMode::PayPerRequest))
    /// }).await?;
    /// ```
    pub async fn create_table<F>(&self, name: &str, callback: F) -> anyhow::Result<()>
    where
        F: FnOnce(CreateTableFluentBuilder) -> Result<CreateTableFluentBuilder, BuildError>,
    {
        let effective_name = self.effective_name(name);

        if self.does_table_exist(name).await? {
            tracing::info!("Table '{}' already exists.", effective_name);
            Ok(())
        } else {
            tracing::info!("Table '{}' does not exist. Creating...", effective_name);
            let _ = callback(self.client.create_table().table_name(&effective_name))
                .with_context(|| {
                    format!(
                        "Faild to build proper create table request for: {}",
                        effective_name
                    )
                })?
                .send()
                .await
                .with_context(|| format!("Failed to create DynamoDB table '{}'", effective_name))?;

            tracing::info!(
                "Create Table '{}' was submitted to DynamoDB",
                effective_name
            );
            self.wait_until_table_becomes_active(&effective_name)
                .await?;
            tracing::info!("Table '{}' was successfully created", effective_name);

            Ok(())
        }
    }

    async fn wait_until_table_becomes_active(&self, table_name: &str) -> anyhow::Result<()> {
        let effective_name = self.effective_name(table_name);
        for _ in 0..15 {
            let resp = self
                .client
                .describe_table()
                .table_name(table_name)
                .send()
                .await
                .with_context(|| format!("Failed to check table status of '{}'", effective_name))?;

            let status = resp
                .table()
                .and_then(|t| t.table_status())
                .unwrap_or(&TableStatus::Creating);

            if status == &TableStatus::Active {
                return Ok(());
            }

            sleep(Duration::from_secs(10)).await;
        }

        anyhow::bail!("Table '{}' did not become ACTIVE in time", effective_name);
    }

    /// Starts a PutItem operation builder for the given table.
    pub fn put_item(&self, table_name: &str) -> PutItemFluentBuilder {
        self.client
            .put_item()
            .table_name(self.effective_name(table_name))
    }

    /// Serializes an entity and creates a PutItem operation.
    ///
    /// Uses `serde_dynamo` to convert the entity to DynamoDB attribute values.
    pub fn put_entity<T: Serialize>(
        &self,
        table_name: &str,
        entity: &T,
    ) -> anyhow::Result<PutItemFluentBuilder> {
        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(entity)
            .context("Error serializing entity into DynamoDB item")?;

        Ok(self.put_item(table_name).set_item(Some(item)))
    }

    /// Starts a GetItem operation builder for the given table.
    pub fn get_item(&self, table_name: &str) -> GetItemFluentBuilder {
        self.client
            .get_item()
            .table_name(self.effective_name(table_name))
    }

    /// Starts a Query operation builder for the given table.
    pub fn query(&self, table_name: &str) -> QueryFluentBuilder {
        self.client
            .query()
            .table_name(self.effective_name(table_name))
    }

    /// Starts an UpdateItem operation builder for the given table.
    pub fn update_item(&self, table_name: &str) -> UpdateItemFluentBuilder {
        self.client
            .update_item()
            .table_name(self.effective_name(table_name))
    }

    /// Starts a DeleteItem operation builder for the given table.
    pub fn delete_item(&self, table_name: &str) -> DeleteItemFluentBuilder {
        self.client
            .delete_item()
            .table_name(self.effective_name(table_name))
    }
}

/// Builder for constructing DynamoDB items with additional attributes.
///
/// Useful when you need to add computed or derived attributes to a serialized entity.
pub struct ItemBuilder {
    item: HashMap<String, AttributeValue>,
}

impl ItemBuilder {
    /// Creates a builder from a serializable entity.
    pub fn from_entity<T: Serialize>(entity: &T) -> anyhow::Result<ItemBuilder> {
        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(entity)
            .context("Error serializing entity into DynamoDB item")?;

        Ok(ItemBuilder { item })
    }

    /// Adds a string attribute to the item.
    pub fn add_str(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let _ = self
            .item
            .insert(key.into(), AttributeValue::S(value.into()));
    }

    /// Consumes the builder and returns the item map.
    pub fn build(self) -> HashMap<String, AttributeValue> {
        self.item
    }
}

#[cfg(test)]
mod tests {
    use crate::aws::dynamodb::client::DynamoClient;
    use crate::aws::test::test_run_id;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
    };
    use std::env;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    #[ignore]
    #[allow(unsafe_code)]
    async fn does_table_exists_detects_nonexistent_table() {
        unsafe {
            env::set_var("DYNAMO_TABLE_PREFIX", "wasabi-test");
        }

        let dbd_client = DynamoClient::from_env().await.unwrap();
        let table_name = "non-existent-table";

        assert!(!dbd_client.does_table_exist(table_name).await.unwrap());
    }

    #[tokio::test]
    #[ignore]
    #[allow(unsafe_code)]
    async fn create_table_actually_creates_a_table() {
        unsafe {
            env::set_var("DYNAMO_TABLE_PREFIX", "wasabi-test");
        }

        let dbd_client = DynamoClient::from_env().await.unwrap();
        let table_name = format!("test-table-{}", test_run_id());

        // Ensure the table does not exist before creating it...
        if dbd_client.does_table_exist(&table_name).await.unwrap() {
            dbd_client
                .client
                .delete_table()
                .table_name(dbd_client.effective_name(&table_name))
                .send()
                .await
                .unwrap();

            // Wait for the table to be deleted...
            for _ in 1..5 {
                if dbd_client.does_table_exist(&table_name).await.unwrap() {
                    tracing::info!("Waiting for table '{}' to be deleted...", table_name);
                    sleep(Duration::from_secs(2)).await;
                } else {
                    break;
                }
            }
        }

        // Check again to ensure the table is deleted...
        assert!(!dbd_client.does_table_exist(&table_name).await.unwrap());

        // Create the table...
        dbd_client
            .create_table(&table_name, |builder| {
                Ok(builder
                    .attribute_definitions(
                        AttributeDefinition::builder()
                            .attribute_name("PK")
                            .attribute_type(ScalarAttributeType::S)
                            .build()
                            .unwrap(),
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name("PK")
                            .key_type(KeyType::Hash)
                            .build()
                            .unwrap(),
                    )
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await
            .unwrap();

        // Ensure the table is created...
        assert!(dbd_client.does_table_exist(&table_name).await.unwrap());

        // Ensure that the table is not created twice...
        dbd_client
            .create_table(&table_name, |_| {
                panic!("This should not be called again");
            })
            .await
            .unwrap();

        // Be a good citizen and delete the table...
        dbd_client
            .client
            .delete_table()
            .table_name(dbd_client.effective_name(&table_name))
            .send()
            .await
            .unwrap();
    }
}
