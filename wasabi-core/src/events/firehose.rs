//! AWS Firehose event recorder with batching.
//!
//! Events are buffered in memory and flushed to Firehose either when the buffer
//! reaches 64 events or every 15 seconds, whichever comes first. This reduces
//! API calls while keeping latency reasonable.
//!
//! The recorder spawns a background task that respects the application shutdown
//! signal, flushing remaining events before exiting.

use crate::events::{Event, EventRecorder};
use crate::tools::system;
use crate::{APP_NAME, CLUSTER_ID};
use async_trait::async_trait;
use aws_sdk_firehose::Client;
use aws_sdk_firehose::config::http::HttpResponse;
use aws_sdk_firehose::error::SdkError;
use aws_sdk_firehose::operation::put_record_batch::{PutRecordBatchError, PutRecordBatchOutput};
use aws_sdk_firehose::types::Record;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;
use std::env;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::mpsc;

/// Regex for normalizing names to lowercase alphanumeric with underscores.
static NON_CHARS: LazyLock<Regex> = LazyLock::new(|| {
    // This regex pattern is static and known-valid at compile time
    #[expect(clippy::unwrap_used, reason = "static regex pattern is always valid")]
    Regex::new(r"[^a-z0-9]+").unwrap()
});

/// Channel capacity - provides backpressure if Firehose can't keep up.
const EVENT_BUFFER_SIZE: usize = 8192;

/// Time-based flush interval to bound event delivery latency.
const EVENT_FLUSH_INTERVAL_SECONDS: u64 = 15;

/// Flush when buffer reaches this size (balances batching efficiency vs latency).
const AUTOMATIC_FLUSH_SIZE: usize = 64;

/// Firehose API limit for PutRecordBatch.
const MAX_EVENTS_PER_UPLOAD: usize = 256;

/// Bound on a single PutRecordBatch call. If Firehose stalls, we must not
/// let the background loop wedge — a wedged loop stops draining the buffer,
/// which then makes every `record_event()` caller block (turning telemetry
/// backpressure into an application-wide hang).
const PUT_RECORD_BATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Envelope that wraps events with metadata before sending to Firehose.
#[derive(Serialize)]
struct EventWrapper<'a, T: Event + Serialize> {
    #[serde(flatten)]
    pub payload: &'a T,

    #[serde(serialize_with = "ts_no_tz")]
    pub timestamp: DateTime<Utc>,
    pub event: &'static str,
    pub system: &'a str,
}

/// Formats timestamp without timezone suffix for Redshift/Athena compatibility.
fn ts_no_tz<S>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
    s.serialize_str(&formatted)
}

/// Lowercases `value` and replaces every run of non-alphanumeric characters with a single `_`.
///
/// This is what turns a host-shaped name into one that survives as a Glue partition value and as a
/// column in a query: `pip.durablox.com` becomes `pip_durablox_com`.
fn normalize(value: &str) -> String {
    NON_CHARS
        .replace_all(&value.to_lowercase(), "_")
        .into_owned()
}

/// The `system` every event of this process is recorded under.
///
/// `FIREHOSE_SYSTEM_NAME` if it is set, otherwise [`CLUSTER_ID`] normalized — the same value
/// [`FirehoseEventRecorder::from_env`] writes into each event's envelope.
///
/// Public because the read side needs it. Events land in a data lake partitioned by `system`, so a
/// query that wants this deployment's own rows has to filter by exactly the string the writer used;
/// a service that derives it a second time for itself is one refactoring away from reading another
/// environment's numbers, or none at all. Deriving it costs nothing, so callers need not hold on to
/// the result.
#[must_use]
pub fn system_name() -> String {
    env::var("FIREHOSE_SYSTEM_NAME").unwrap_or_else(|_| normalize(&CLUSTER_ID))
}

/// Event recorder that batches and streams events to AWS Firehose.
///
/// Create via [`from_env()`](Self::from_env) which reads configuration from
/// environment variables and spawns the background flush task.
pub struct FirehoseEventRecorder {
    system: String,
    tx: mpsc::Sender<String>,
}

impl FirehoseEventRecorder {
    /// Creates a recorder from environment variables and starts the background task.
    ///
    /// # Environment Variables
    /// - `FIREHOSE_STREAM_NAME` - Firehose delivery stream (defaults to normalized `APP_NAME`)
    /// - `FIREHOSE_SYSTEM_NAME` - System identifier in event metadata (defaults to normalized `CLUSTER_ID`)
    #[tracing::instrument(err(level = "debug", Display))]
    pub async fn from_env() -> anyhow::Result<Self> {
        // Bound the Firehose SDK independently so the timeout on
        // PutRecordBatch is enforced by both the tokio wrapper and the
        // AWS SDK. Firehose is telemetry — we favour dropping records
        // over ever blocking the flush loop.
        let timeout_config = aws_config::timeout::TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(3))
            .operation_attempt_timeout(Duration::from_secs(10))
            .operation_timeout(Duration::from_secs(30))
            .build();

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout_config)
            .load()
            .await;
        let client = Client::new(&config);

        let stream = env::var("FIREHOSE_STREAM_NAME").unwrap_or_else(|_| normalize(&APP_NAME));
        let system = system_name();

        tracing::info!(
            "Sending events to Firehose as system: {} into stream: {}",
            system,
            stream
        );

        let (tx, rx) = mpsc::channel::<String>(EVENT_BUFFER_SIZE);
        drop(tokio::spawn(async move {
            run_background_loop(&client, &stream, rx).await;
        }));

        Ok(Self { system, tx })
    }

    async fn record_event<'a, E: Event>(&self, event: EventWrapper<'a, E>) -> anyhow::Result<()> {
        let json = serde_json::to_string(&event)?;

        // Use try_send: telemetry must never block business logic. If the
        // consumer is stuck (Firehose down, network wedged), events are
        // dropped and logged rather than propagating backpressure into
        // every handler.
        match self.tx.try_send(json) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    buffer_capacity = EVENT_BUFFER_SIZE,
                    "Firehose event buffer full, dropping event",
                );
                Ok(())
            }
            Err(err @ mpsc::error::TrySendError::Closed(_)) => Err(err.into()),
        }
    }
}

async fn run_background_loop(client: &Client, stream: &str, mut rx: mpsc::Receiver<String>) {
    let mut buffer = Vec::new();
    let mut interval = tokio::time::interval(Duration::from_secs(EVENT_FLUSH_INTERVAL_SECONDS));

    while system::is_running() {
        tokio::select! {
            Some(event) = rx.recv() => {
                buffer.push(event);
                if buffer.len() >= AUTOMATIC_FLUSH_SIZE {
                    flush_batch(client, stream, &mut buffer).await;
                }
            },
            _ = interval.tick() => {
                    flush_batch(client, stream, &mut buffer).await;
            }
        }
    }

    // Channel closed, flush remaining events...
    flush_batch(client, stream, &mut buffer).await;
}

async fn flush_batch(client: &Client, stream: &str, buffer: &mut Vec<String>) {
    if !buffer.is_empty() {
        do_flush_batch(client, stream, buffer).await;
    }
}

#[tracing::instrument(level = "debug", skip(client, buffer))]
async fn do_flush_batch(client: &Client, stream: &str, buffer: &mut Vec<String>) {
    let records = buffer
        .drain(..)
        .flat_map(|json| Record::builder().data(json.into_bytes().into()).build())
        .collect::<Vec<_>>();

    for chunk in records.chunks(MAX_EVENTS_PER_UPLOAD) {
        if let Err(err) = flush_chunk(client, stream, chunk).await {
            tracing::error!(?err, "Failed to send batch of events to Firehose");
        }
    }
}

#[tracing::instrument(level = "debug", skip(client, chunk))]
async fn flush_chunk(
    client: &Client,
    stream: &str,
    chunk: &[Record],
) -> anyhow::Result<PutRecordBatchOutput> {
    let send = client
        .put_record_batch()
        .delivery_stream_name(stream)
        .set_records(Some(chunk.into()))
        .send();

    match tokio::time::timeout(PUT_RECORD_BATCH_TIMEOUT, send).await {
        Ok(inner) => {
            inner.map_err(|err: SdkError<PutRecordBatchError, HttpResponse>| anyhow::anyhow!(err))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Timed out after {}s calling Firehose PutRecordBatch",
            PUT_RECORD_BATCH_TIMEOUT.as_secs()
        )),
    }
}

#[async_trait]
impl EventRecorder for FirehoseEventRecorder {
    async fn record<E: Event>(&self, event: E) {
        self.record_at(event, Utc::now()).await;
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn record_at<E: Event>(&self, event: E, timestamp: DateTime<Utc>) {
        let wrapper = EventWrapper {
            payload: &event,
            timestamp,
            event: event.event_type(),
            system: &self.system,
        };

        if let Err(err) = self.record_event(wrapper).await {
            tracing::error ! ( ? event, % timestamp, ? err, "Failed to record event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape that actually occurs: a cluster id is a host name, and the dots have to go or the
    /// value cannot be a partition.
    #[test]
    fn normalize_turns_a_host_name_into_a_partition_value() {
        assert_eq!(normalize("pip.durablox.com"), "pip_durablox_com");
    }

    #[test]
    fn normalize_lowercases() {
        assert_eq!(normalize("PIP-Core"), "pip_core");
    }

    /// A run of separators collapses into one `_`, so two spellings of the same name cannot end up
    /// as two partitions.
    #[test]
    fn normalize_collapses_a_run_of_separators() {
        assert_eq!(normalize("pip -- core"), "pip_core");
    }
}
