//! DynamoDB client and query utilities.
//!
//! Provides ergonomic wrappers for common DynamoDB operations:
//!
//! - [`client::DynamoClient`] - Table-prefixed client for CRUD operations
//! - [`schema`] - Helpers for defining table schemas and indexes
//! - Query helpers for pagination and entity deserialization
//!
//! # Environment Variables
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `DYNAMO_TABLE_PREFIX` | Prefix for all table names (required) |
//!
//! # Table Naming
//!
//! All table names are prefixed with `DYNAMO_TABLE_PREFIX`:
//! - Logical name: `users`
//! - Effective name: `{DYNAMO_TABLE_PREFIX}-users`

use anyhow::Context;
use aws_sdk_dynamodb::config::http::HttpResponse;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::query::QueryOutput;
use aws_sdk_dynamodb::operation::query::builders::QueryFluentBuilder;
use aws_sdk_dynamodb::types::AttributeValue;
use futures_util::{Stream, StreamExt, TryStreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::pin::Pin;

pub mod client;
pub mod schema;

/// Extracts the first entity from a query result.
pub fn extract_entity<T: Serialize + DeserializeOwned>(
    output: QueryOutput,
) -> anyhow::Result<Option<T>> {
    let first = output.items.and_then(|items| items.into_iter().next());
    deserialize_entity(first)
}

/// Deserializes a DynamoDB item into an entity.
pub fn deserialize_entity<T: Serialize + DeserializeOwned>(
    values: Option<HashMap<String, AttributeValue>>,
) -> anyhow::Result<Option<T>> {
    if let Some(items) = values {
        Ok(Some(
            serde_dynamo::aws_sdk_dynamodb_1::from_item(items)
                .context("Failed to deserialize DynamoDB item")?,
        ))
    } else {
        Ok(None)
    }
}

/// Checks if a PutItem error is a conditional check failure.
pub fn is_conditional_check_failed(err: &SdkError<PutItemError, HttpResponse>) -> bool {
    err.as_service_error()
        .map(PutItemError::is_conditional_check_failed_exception)
        .unwrap_or_default()
}

/// Finds the first entity matching a query, handling pagination internally.
pub async fn find_first<E: Serialize + DeserializeOwned>(
    query_fluent_builder: QueryFluentBuilder,
) -> anyhow::Result<Option<E>> {
    let block_size = query_fluent_builder
        .get_limit()
        .context("Invalid query: No limit is given")?;

    let mut last_key = None;

    loop {
        let mut query = query_fluent_builder.clone();
        query = query.set_exclusive_start_key(last_key);
        let result = query
            .send()
            .await
            .context("Error searching table 'blocks'")?;

        if result.count() > 0 {
            return extract_entity(result).context("Failed to deserialize an entity");
        } else if result.scanned_count() < block_size || result.last_evaluated_key().is_none() {
            return Ok(None);
        } else {
            last_key = result.last_evaluated_key;
        }
    }
}

/// Returns a stream of entities from a paginated query.
///
/// Automatically handles DynamoDB pagination, yielding entities one at a time.
/// The query must have a limit set.
pub fn stream_all<E>(
    query_fluent_builder: QueryFluentBuilder,
) -> anyhow::Result<Pin<Box<dyn Stream<Item = anyhow::Result<E>> + Send>>>
where
    E: Serialize + DeserializeOwned + Send + 'static,
{
    enum PaginationState {
        Start,
        LastKey(HashMap<String, AttributeValue>),
        End,
    }

    let _ = query_fluent_builder
        .get_limit()
        .context("Invalid query: No limit is given")?;

    let stream = futures_util::stream::try_unfold(
        (query_fluent_builder, PaginationState::Start),
        |(query_fluent_builder, state)| async move {
            let mut query = query_fluent_builder.clone();
            match state {
                PaginationState::Start => {}
                PaginationState::LastKey(last_key) => {
                    query = query.set_exclusive_start_key(Some(last_key));
                }
                PaginationState::End => return Ok::<_, anyhow::Error>(None),
            }

            let result = query
                .send()
                .await
                .context("Error executing paginated query")?;

            let entities = result
                .items
                .unwrap_or_default()
                .into_iter()
                .map(serde_dynamo::aws_sdk_dynamodb_1::from_item)
                .collect::<Result<Vec<E>, _>>()
                .context("Failed to deserialize items")?;

            if entities.is_empty() {
                Ok(None)
            } else {
                let next_state = if let Some(next_key) = result.last_evaluated_key {
                    PaginationState::LastKey(next_key)
                } else {
                    PaginationState::End
                };

                Ok(Some((entities, (query_fluent_builder, next_state))))
            }
        },
    );

    let stream = stream
        .map_ok(|items| futures_util::stream::iter(items.into_iter().map(Ok)))
        .try_flatten()
        .boxed();

    Ok(stream)
}

/// Collects all entities matching a query into a vector.
///
/// Convenience wrapper around [`stream_all`] that collects results.
pub async fn find_all<E>(query_fluent_builder: QueryFluentBuilder) -> anyhow::Result<Vec<E>>
where
    E: Serialize + DeserializeOwned + Send + 'static,
{
    stream_all(query_fluent_builder)?.try_collect().await
}

/// Generates a 32-character random ID suitable for DynamoDB keys.
pub fn generate_id() -> String {
    crate::tools::id_generator::generate_id(32)
}

/// Creates a string [`AttributeValue`] from any string-like type.
pub fn str(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestEntity {
        id: String,
        name: String,
        count: i32,
    }

    #[test]
    fn deserialize_entity_returns_none_for_none() {
        let result: anyhow::Result<Option<TestEntity>> = deserialize_entity(None);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn deserialize_entity_deserializes_valid_item() {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S("123".to_string()));
        item.insert("name".to_string(), AttributeValue::S("test".to_string()));
        item.insert("count".to_string(), AttributeValue::N("42".to_string()));

        let result: Option<TestEntity> = deserialize_entity(Some(item)).unwrap();

        assert_eq!(
            result,
            Some(TestEntity {
                id: "123".to_string(),
                name: "test".to_string(),
                count: 42,
            })
        );
    }

    #[test]
    fn str_creates_string_attribute_value() {
        let attr = str("hello");
        assert_eq!(attr, AttributeValue::S("hello".to_string()));
    }

    #[test]
    fn generate_id_returns_32_char_string() {
        let id = generate_id();
        assert_eq!(id.len(), 32);
    }
}
