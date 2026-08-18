//! Warp framework utilities and HTTP server setup.
//!
//! Provides filters for parsing request bodies (JSON, form, raw bytes/streams),
//! response helpers, error handling, and the main [`run_webserver`] function
//! that sets up tracing and graceful shutdown.

use crate::client_bail;
use crate::web::error::{ApiError, ResultExt};
use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use percent_encoding::percent_decode_str;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BufMut;
use tracing::debug_span;
use warp::http::header::CONTENT_TYPE;
use warp::http::{HeaderValue, StatusCode};
use warp::reply::Response;
use warp::{Filter, Rejection, Reply, http, reply};

use crate::tools::{PinnedBytesStream, system};

/// Filter that extracts the Content-Length header as u64.
pub fn content_length_header() -> impl Filter<Extract = (u64,), Error = Rejection> + Clone {
    warp::header::header::<u64>(http::header::CONTENT_LENGTH.as_str())
}

/// Filter that injects a cloneable value into the filter chain.
pub fn with_cloneable<C: Clone + Send>(
    value: C,
) -> impl Filter<Extract = (C,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

/// Filter that reads the request body into a `Vec<u8>`, enforcing size limits.
pub fn with_body_as_buffer(
    max_body_size: u64,
) -> impl Filter<Extract = (Vec<u8>,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async move |stream, content_length, max_body_size| {
            body_as_buffer(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn body_as_buffer(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<Vec<u8>> {
    if content_length == 0 {
        client_bail!("Empty input data");
    }
    if content_length > max_body_size {
        client_bail!("The given request data is too large");
    }

    let stream = as_size_limited_stream(stream, content_length).await;
    read_into_buffer(stream, content_length).await
}

async fn as_size_limited_stream<E: Error + Send + Sync + 'static>(
    stream: impl Stream<Item = Result<impl Buf, E>> + Unpin + Send,
    content_length: u64,
) -> impl Stream<Item = Result<impl Buf, std::io::Error>> {
    let mut remaining_bytes = content_length as i64;

    stream.map(move |result| match result {
        Ok(bytes) => {
            remaining_bytes -= bytes.remaining() as i64;
            if remaining_bytes < 0 {
                Err(std::io::Error::other(anyhow!("Input data too large")))
            } else {
                Ok(bytes)
            }
        }
        Err(err) => Err(std::io::Error::other(err)),
    })
}

fn buf_to_bytes(mut buf: impl Buf) -> Bytes {
    let len = buf.remaining();
    let mut vec = vec![0u8; len];
    buf.copy_to_slice(&mut vec);
    Bytes::from(vec)
}

/// Filter that provides the request body as a streaming `PinnedBytesStream`.
pub fn with_body_as_stream(
    max_content_size: u64,
) -> impl Filter<Extract = (PinnedBytesStream,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_content_size))
        .and_then(async move |stream, content_length, max_content_size| {
            as_stream(
                as_size_limited_stream(stream, content_length).await,
                content_length,
                max_content_size,
            )
            .await
            .map_err(into_rejection)
        })
}

async fn as_stream(
    stream: impl Stream<Item = Result<impl Buf + 'static, std::io::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<PinnedBytesStream> {
    if content_length == 0 {
        client_bail!("Empty input data");
    }
    if content_length > max_body_size {
        client_bail!("The given request data is too large");
    }

    let pinned: PinnedBytesStream = Box::pin(stream.map_ok(buf_to_bytes));
    Ok(pinned)
}

/// Reads a byte stream into a pre-allocated buffer.
pub async fn read_into_buffer(
    mut stream: impl Stream<Item = Result<impl Buf, std::io::Error>> + Unpin,
    content_length: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(content_length as usize);
    while let Some(chunk) = stream
        .try_next()
        .await
        .context("Failed to read body")
        .mark_client_error()?
    {
        data.put(chunk);
    }

    Ok(data)
}

/// Filter that parses the request body as JSON into type `T`.
pub fn with_body_as_json<T: DeserializeOwned + Send>(
    max_body_size: u64,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            decode_json(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn decode_json<T: DeserializeOwned + Send>(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<T> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let decoded = serde_json::from_slice(&data)
        .context("Invalid JSON input")
        .mark_client_error()?;

    Ok(decoded)
}

/// Filter that parses URL-encoded form data into type `T`.
pub fn with_body_as_form<T: DeserializeOwned + Send>(
    max_body_size: u64,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone {
    warp::header::exact_ignore_case("content-type", "application/x-www-form-urlencoded")
        .and(warp::body::stream())
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            decode_form(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn decode_form<T: DeserializeOwned + Send>(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<T> {
    let data = body_as_string(stream, content_length, max_body_size).await?;
    let decoded = serde_urlencoded::from_str(&data)
        .context("Invalid url-encoded data input")
        .mark_client_error()?;

    Ok(decoded)
}

/// Filter that reads the request body as a UTF-8 string.
pub fn with_body_as_string(
    max_body_size: u64,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::body::stream()
        .and(content_length_header())
        .and(with_cloneable(max_body_size))
        .and_then(async |stream, content_length, max_body_size| {
            body_as_string(stream, content_length, max_body_size)
                .await
                .map_err(into_rejection)
        })
}

async fn body_as_string(
    stream: impl Stream<Item = Result<impl Buf + Send + 'static, warp::Error>> + Unpin + Send + 'static,
    content_length: u64,
    max_body_size: u64,
) -> anyhow::Result<String> {
    let data = body_as_buffer(stream, content_length, max_body_size).await?;
    let data_as_string = String::from_utf8(data)
        .context("Received invalid UTF-8 data")
        .mark_client_error()?;

    Ok(data_as_string)
}
/// Converts a result into a JSON response with status 200 OK.
pub fn into_response<S: Serialize>(result: anyhow::Result<S>) -> Result<impl Reply, Rejection> {
    into_response_with_status(result.map(|data| (StatusCode::OK, data)))
}

/// Converts a result into a JSON response with a custom status code.
pub fn into_response_with_status<S: Serialize>(
    response: anyhow::Result<(StatusCode, S)>,
) -> Result<impl Reply, Rejection> {
    let response = response.and_then(|(status_code, data)| {
        match serde_json::to_vec(&data).context("Failed to serialize data") {
            Ok(data) => Ok((status_code, data)),
            Err(err) => Err(err),
        }
    });

    match response {
        Ok((status, data)) => {
            let mut res = Response::new(data.into());
            *res.status_mut() = status;
            let _ = res
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            Ok(res)
        }
        Err(err) => Err(into_rejection(err)),
    }
}

/// Converts an anyhow error into a warp Rejection, preserving ApiError status if present.
pub fn into_rejection(err: anyhow::Error) -> Rejection {
    match err.downcast_ref::<ApiError>() {
        Some(api_error) => api_error.clone().into(),
        None => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", err)).into(),
    }
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(err) = err.find::<ApiError>() {
        Ok(reply::with_status(reply::json(&err), err.status))
    } else {
        Err(err)
    }
}

/// Combines multiple routes using `or`. Usage: `routes![route1, route2, route3]`
#[macro_export]
macro_rules! routes {
    [$route:expr] => {
        $route
    };
    [$route:expr, $($rest:expr),+] => {
        warp::Filter::or($route, routes![$($rest),+])
    };
}

/// Creates a tracing filter that wraps requests with a span.
///
/// Each request gets a `debug_span!("http_request")` that tracks method, path,
/// and status code. With OpenTelemetry enabled, also extracts parent context
/// from incoming headers.
fn tracing_filter() -> warp::trace::Trace<impl Fn(warp::trace::Info<'_>) -> tracing::Span + Clone> {
    warp::trace::trace(|info: warp::trace::Info<'_>| {
        #[cfg_attr(not(feature = "open_telemetry"), allow(unused_mut))]
        let mut span = debug_span!(
            "http_request",
            aws.service = crate::CLUSTER_ID.clone(),
            http.method = %info.method(),
            http.url = %info.path(),
            http.status_code = tracing::field::Empty,
        );

        #[cfg(feature = "open_telemetry")]
        open_telemetry::extract_parent_context(info.request_headers(), &mut span);

        span
    })
}

/// Converts any [`Reply`] into a [`Response`] and records its status code on the
/// current `http_request` span.
///
/// Runs inside the [`tracing_filter`] span, so `Span::current()` resolves to the
/// per-request span created for this request.
fn record_status<R: Reply>(reply: R) -> Response {
    let response = reply.into_response();
    let _ = tracing::Span::current().record("http.status_code", response.status().as_u16() as i64);
    response
}

/// Starts an HTTP server with tracing and graceful shutdown.
///
/// Reads `BIND_ADDRESS` from environment. Waits for shutdown signal,
/// then allows 3 seconds for in-flight requests to complete.
pub async fn run_webserver<F>(routes: F) -> anyhow::Result<()>
where
    F: Filter + Clone + Send + Sync + 'static,
    F::Extract: Reply,
    F::Error: Into<Rejection> + 'static,
{
    let bind_address = env::var("BIND_ADDRESS")
        .context("Failed to read bind address. Please provide BIND_ADDRESS in the environment")?;
    let bind_address =
        SocketAddr::from_str(&bind_address).context("Failed to parse bind address.")?;

    tracing::info!("Starting server at {}", bind_address);

    // Recover first so rejections become responses, then map the unified reply
    // to record the final status on the current `http_request` span, and only
    // then wrap everything in the tracing filter. This keeps the span active
    // (via `warp::trace`) while the status is recorded, and ensures recovered
    // rejections are traced with their status too.
    let filter = routes
        .boxed()
        .recover(handle_rejection)
        .map(record_status)
        .with(tracing_filter());

    tracing::info!("Running HTTP server at {}", bind_address);

    warp::serve(filter)
        .bind(bind_address)
        .await
        .graceful(system::await_shutdown())
        .run()
        .await;

    tracing::info!("HTTP Server has been stopped...");
    // Wait a bit to ensure all requests are processed and also permit background tasks to finish
    // (as most probably the web server will run in the main thread which will cause the process
    // to terminate once it completes).
    tokio::time::sleep(Duration::from_secs(3)).await;
    tracing::info!("HTTP Server has been terminated.");

    Ok(())
}

/// A URL path segment that has been percent-decoded.
///
/// Use in route patterns to automatically decode path segments like `%20` → ` `.
#[derive(Debug, Clone)]
pub struct DecodedSegment(pub String);

impl FromStr for DecodedSegment {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "%20" -> " "
        let decoded = percent_decode_str(s).decode_utf8_lossy().into_owned();
        Ok(DecodedSegment(decoded))
    }
}

impl From<DecodedSegment> for String {
    fn from(value: DecodedSegment) -> Self {
        value.0
    }
}

#[cfg(feature = "open_telemetry")]
mod open_telemetry {
    use opentelemetry::propagation::Extractor;
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use warp::http::HeaderMap;

    struct HeaderExtractor<'a> {
        headers: &'a HeaderMap,
    }

    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.headers.get(key).and_then(|value| value.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.headers.keys().map(|header| header.as_str()).collect()
        }
    }

    pub fn extract_parent_context(headers: &HeaderMap, span: &mut Span) {
        let extractor = HeaderExtractor { headers };
        let parent_cx =
            opentelemetry::global::get_text_map_propagator(|prop| prop.extract(&extractor));
        let _ = span.set_parent(parent_cx);
    }
}

/// Build a keep-alive SSE reply from an event stream that is `Send` but may be `!Sync`.
///
/// warp 0.4 / hyper 1.x require an SSE event stream to be `Send + Sync`. Streams that
/// `await` AWS SDK (aws-smithy) futures — Bedrock, DynamoDB, Firehose — are `Send`-only,
/// so any handler that yields SSE events while touching AWS is `!Sync` and cannot be
/// passed to [`warp::sse::reply`] directly.
///
/// This drives `events` on a detached task and re-emits each item through a bounded
/// channel; the channel receiver is `Send + Sync`, so route handlers get a working SSE
/// reply without laundering the stream by hand. The bounded capacity preserves
/// backpressure onto the producer. The task ends when the producer finishes or the
/// client disconnects (the receiver is dropped).
pub fn sse_keep_alive_reply<S, E>(events: S) -> Response
where
    S: Stream<Item = Result<warp::sse::Event, E>> + Send + 'static,
    E: Error + Send + Sync + 'static,
{
    use futures::SinkExt;

    let (mut tx, rx) = futures::channel::mpsc::channel(32);
    let _drive = tokio::spawn(async move {
        futures::pin_mut!(events);
        while let Some(event) = events.next().await {
            if tx.send(event).await.is_err() {
                // Client disconnected: stop driving the producer.
                break;
            }
        }
    });

    warp::sse::reply(warp::sse::keep_alive().stream(rx)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::error::ApiError;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use futures_util::stream;
    use std::str::FromStr;

    // as_size_limited_stream tests

    #[tokio::test]
    async fn as_size_limited_stream_allows_valid_size() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from("hello"))]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert!(result.iter().all(Result::is_ok));
    }

    #[tokio::test]
    async fn as_size_limited_stream_rejects_oversize_input() {
        let stream = stream::iter(vec![
            Ok::<Bytes, warp::Error>(Bytes::from("hello")),
            Ok::<Bytes, warp::Error>(Bytes::from("world")),
            Ok::<Bytes, warp::Error>(Bytes::from("foobar")),
        ]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert_eq!(result.iter().filter(|res| res.is_ok()).count(), 1);
        assert_eq!(result.iter().filter(|res| res.is_err()).count(), 2);
    }

    #[tokio::test]
    async fn as_size_limited_stream_handles_empty_input() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(""))]);
        let result: Vec<_> = as_size_limited_stream(stream, 0).await.collect().await;

        assert!(result.iter().all(|res| res.is_ok()));
    }

    #[tokio::test]
    async fn as_size_limited_stream_propagates_stream_errors() {
        let stream = stream::iter(vec![Err::<Bytes, std::io::Error>(std::io::Error::other(
            "Test error",
        ))]);
        let result: Vec<_> = as_size_limited_stream(stream, 5).await.collect().await;

        assert!(result.iter().any(|res| res.is_err()));
    }

    // into_rejection tests

    #[test]
    fn into_rejection_preserves_api_error_status() {
        // Create an error with ApiError context
        let err: anyhow::Error = anyhow::anyhow!("root cause")
            .context(ApiError::new(StatusCode::NOT_FOUND, "Not found"));

        let rejection = into_rejection(err);

        let found = rejection.find::<ApiError>().unwrap();
        assert_eq!(found.status, StatusCode::NOT_FOUND);
        assert_eq!(found.message, "Not found");
    }

    #[test]
    fn into_rejection_defaults_to_500_for_plain_errors() {
        let err = anyhow::anyhow!("Something went wrong");

        let rejection = into_rejection(err);

        let found = rejection.find::<ApiError>().unwrap();
        assert_eq!(found.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(found.message.contains("Something went wrong"));
    }

    // DecodedSegment tests

    #[test]
    fn decoded_segment_decodes_percent_encoding() {
        let segment = DecodedSegment::from_str("hello%20world").unwrap();
        assert_eq!(segment.0, "hello world");
    }

    #[test]
    fn decoded_segment_decodes_special_chars() {
        let segment = DecodedSegment::from_str("foo%2Fbar").unwrap();
        assert_eq!(segment.0, "foo/bar");

        let segment = DecodedSegment::from_str("a%3Db").unwrap();
        assert_eq!(segment.0, "a=b");
    }

    #[test]
    fn decoded_segment_passes_through_plain_text() {
        let segment = DecodedSegment::from_str("hello").unwrap();
        assert_eq!(segment.0, "hello");
    }

    #[test]
    fn decoded_segment_converts_to_string() {
        let segment = DecodedSegment::from_str("test").unwrap();
        let s: String = segment.into();
        assert_eq!(s, "test");
    }

    // read_into_buffer tests

    #[tokio::test]
    async fn read_into_buffer_collects_chunks() {
        let stream = stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from("hel")),
            Ok(Bytes::from("lo")),
        ]);
        let result = read_into_buffer(stream, 5).await.unwrap();
        assert_eq!(result, b"hello");
    }

    #[tokio::test]
    async fn read_into_buffer_handles_empty_stream() {
        let stream = stream::iter(Vec::<Result<Bytes, std::io::Error>>::new());
        let result = read_into_buffer(stream, 0).await.unwrap();
        assert!(result.is_empty());
    }

    // buf_to_bytes tests

    #[test]
    fn buf_to_bytes_converts_buffer() {
        let buf = Bytes::from("hello");
        let result = buf_to_bytes(buf);
        assert_eq!(result, Bytes::from("hello"));
    }

    #[test]
    fn buf_to_bytes_handles_empty_buffer() {
        let buf = Bytes::new();
        let result = buf_to_bytes(buf);
        assert!(result.is_empty());
    }

    // body_as_buffer tests

    #[tokio::test]
    async fn body_as_buffer_reads_valid_body() {
        let stream = stream::iter(vec![
            Ok::<Bytes, warp::Error>(Bytes::from("hello")),
            Ok(Bytes::from(" world")),
        ]);
        let result = body_as_buffer(stream, 11, 100).await.unwrap();
        assert_eq!(result, b"hello world");
    }

    #[tokio::test]
    async fn body_as_buffer_rejects_empty_content_length() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::new())]);
        let result = body_as_buffer(stream, 0, 100).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty"));
    }

    #[tokio::test]
    async fn body_as_buffer_rejects_oversized_content_length() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from("data"))]);
        let result = body_as_buffer(stream, 1000, 100).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    // as_stream tests

    #[tokio::test]
    async fn as_stream_returns_stream_for_valid_input() {
        let stream = stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from("test"))]);
        let result = as_stream(stream, 4, 100).await;

        assert!(result.is_ok());
        let mut pinned = result.unwrap();
        let first = pinned.next().await.unwrap().unwrap();
        assert_eq!(first, Bytes::from("test"));
    }

    #[tokio::test]
    async fn as_stream_rejects_empty_content_length() {
        let stream = stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::new())]);
        let result = as_stream(stream, 0, 100).await;

        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("Empty"));
    }

    #[tokio::test]
    async fn as_stream_rejects_oversized_content() {
        let stream = stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from("data"))]);
        let result = as_stream(stream, 1000, 100).await;

        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("too large"));
    }

    // body_as_string tests

    #[tokio::test]
    async fn body_as_string_reads_valid_utf8() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from("hello"))]);
        let result = body_as_string(stream, 5, 100).await.unwrap();
        assert_eq!(result, "hello");
    }

    #[tokio::test]
    async fn body_as_string_rejects_invalid_utf8() {
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(vec![
            0xff, 0xfe, 0x00, 0x01,
        ]))]);
        let result = body_as_string(stream, 4, 100).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UTF-8"));
    }

    // decode_json tests

    #[tokio::test]
    async fn decode_json_parses_valid_json() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct TestData {
            name: String,
            value: i32,
        }

        let json = r#"{"name": "test", "value": 42}"#;
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(json))]);
        let result: TestData = decode_json(stream, json.len() as u64, 1000).await.unwrap();

        assert_eq!(
            result,
            TestData {
                name: "test".to_string(),
                value: 42
            }
        );
    }

    #[tokio::test]
    async fn decode_json_rejects_invalid_json() {
        #[derive(serde::Deserialize, Debug)]
        struct TestData {
            #[allow(dead_code)]
            name: String,
        }

        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from("not json"))]);
        let result: Result<TestData, _> = decode_json(stream, 8, 1000).await;

        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("Invalid JSON"));
    }

    // decode_form tests

    #[tokio::test]
    async fn decode_form_parses_valid_form_data() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct FormData {
            username: String,
            password: String,
        }

        let form = "username=alice&password=secret";
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(form))]);
        let result: FormData = decode_form(stream, form.len() as u64, 1000).await.unwrap();

        assert_eq!(
            result,
            FormData {
                username: "alice".to_string(),
                password: "secret".to_string()
            }
        );
    }

    #[tokio::test]
    async fn decode_form_handles_url_encoded_values() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct FormData {
            query: String,
        }

        let form = "query=hello%20world";
        let stream = stream::iter(vec![Ok::<Bytes, warp::Error>(Bytes::from(form))]);
        let result: FormData = decode_form(stream, form.len() as u64, 1000).await.unwrap();

        assert_eq!(
            result,
            FormData {
                query: "hello world".to_string()
            }
        );
    }

    // into_response tests

    #[test]
    fn into_response_serializes_success() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Response {
            message: String,
        }

        let result: anyhow::Result<Response> = Ok(Response {
            message: "ok".to_string(),
        });
        let response = into_response(result).unwrap();
        let response = response.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn into_response_converts_error_to_rejection() {
        let result: anyhow::Result<String> = Err(anyhow::anyhow!("Something failed"));
        let response = into_response(result);

        assert!(response.is_err());
    }

    // into_response_with_status tests

    #[test]
    fn into_response_with_status_uses_custom_status() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Created {
            id: u64,
        }

        let result: anyhow::Result<(StatusCode, Created)> =
            Ok((StatusCode::CREATED, Created { id: 123 }));
        let response = into_response_with_status(result).unwrap();
        let response = response.into_response();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[test]
    fn into_response_with_status_preserves_api_error() {
        use crate::web::error::ResultExt;

        // Create an error with ApiError via the ResultExt trait
        let result: anyhow::Result<(StatusCode, String)> = Err(anyhow::anyhow!("root cause"))
            .context("wrapped")
            .with_status(StatusCode::BAD_REQUEST);

        let response = into_response_with_status(result);

        assert!(response.is_err());
        let rejection = response.err().unwrap();
        let api_error = rejection.find::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::BAD_REQUEST);
    }
}
