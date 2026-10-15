//! Event recording system for analytics and audit trails.
//!
//! Provides a trait-based abstraction over event sinks. Events are typed structs
//! that implement [`Event`] (via derive macro) and get serialized to JSON before
//! being sent to the configured backend.
//!
//! Use [`NoopEventRecorder`] during development or when event recording is disabled.
//! In production, use `firehose::FirehoseEventRecorder` (feature `aws_firehose`) to stream events
//! to AWS.

#[cfg(feature = "aws_firehose")]
pub mod firehose;

use async_trait::async_trait;
use serde::Serialize;
use std::fmt::Debug;

/// A typed event that can be recorded.
///
/// Implement this trait using the `#[derive(Event)]` macro from `wasabi_macro`.
/// The event type string is used for routing and filtering in downstream systems.
pub trait Event: Serialize + Debug + Send + Sync {
    /// Returns a static string identifying this event type (e.g., "user_login", "order_placed").
    fn event_type(&self) -> &'static str;
}

/// Async event sink abstraction.
///
/// Implementations handle serialization, batching, and delivery to the backend.
#[async_trait]
pub trait EventRecorder: Send + Sync {
    /// Records an event with the current timestamp.
    async fn record<E: Event>(&self, event: E);

    /// Records an event with a specific timestamp (for backfilling or delayed processing).
    async fn record_at<E: Event>(&self, event: E, timestamp: chrono::DateTime<chrono::Utc>);
}

/// Development/testing recorder that logs events instead of sending them.
pub struct NoopEventRecorder;

#[async_trait]
impl EventRecorder for NoopEventRecorder {
    async fn record<E: Event>(&self, event: E) {
        self.record_at(event, chrono::Utc::now()).await;
    }
    async fn record_at<E: Event>(&self, event: E, timestamp: chrono::DateTime<chrono::Utc>) {
        match serde_json::to_string(&event) {
            Ok(json) => {
                tracing::debug!(
                    "Received an event of type {} at {}: {}",
                    event.event_type(),
                    timestamp,
                    json
                );
            }
            Err(err) => {
                tracing::error!(
                    "Failed to serialize event of type {} at {}: {:#}",
                    event.event_type(),
                    timestamp,
                    err
                );
            }
        }
    }
}
