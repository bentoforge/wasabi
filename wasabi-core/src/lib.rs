//! # Wasabi Core
//!
//! A lightweight Rust microservices framework for containerized deployments.
//!
//! Wasabi provides the building blocks for creating robust, observable web services
//! with minimal boilerplate. It's designed for AWS-centric deployments but works
//! anywhere you can run containers.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use wasabi_core::web::warp::run_webserver;
//! use wasabi_core::logging;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     logging::init_tracing().await;
//!
//!     let routes = warp::path("health").map(|| "OK");
//!     run_webserver(routes).await
//! }
//! ```
//!
//! ## Modules
//!
//! - [`logging`] - Tracing setup with optional OpenTelemetry export
//! - [`web`] - HTTP server, JWT authentication, request/response utilities
//! - [`aws`] - AWS service integrations (S3, DynamoDB, Bedrock, SES)
//! - [`events`] - Event recording with Firehose batching
//! - [`tools`] - Utilities (ID generation, i18n strings, graceful shutdown)
//! - [`opensearch`] - OpenSearch/Elasticsearch client (feature-gated)
//! - [`postgres`] - PostgreSQL pool, records and schema diff (feature-gated)
//!
//! ## Feature Flags
//!
//! All integrations are opt-in to keep compile times fast:
//!
//! - `pretty_logs` - Colorful console output for development
//! - `open_telemetry` - OpenTelemetry tracing export
//! - `aws_s3` - S3 client with caching and multipart upload
//! - `aws_dynamodb` - DynamoDB integration
//! - `aws_firehose` - Firehose event streaming
//! - `aws_bedrock` - Bedrock AI model integration
//! - `aws_ses` - Outbound mail via SES
//! - `open_search` - OpenSearch client
//! - `postgres` - PostgreSQL pool, records and declarative table schemas
//!
//! ## Environment Variables
//!
//! The framework reads configuration from environment variables:
//!
//! ### Core
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `APP_NAME` | Application identifier | `WASABI` |
//! | `APP_VERSION` | Version string | `DEVELOPMENT-SNAPSHOT-VERSION` |
//! | `CLUSTER_ID` | Cluster/service identifier | `local` |
//! | `TASK_ID` | Task/instance identifier | `local` |
//! | `BIND_ADDRESS` | HTTP server bind address | (required) |
//!
//! ### Authentication
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `AUTH_SECRET` | JWT shared secret for HMAC validation | (optional) |
//! | `AUTH_ALGORITHMS` | Comma-separated list of allowed JWT algorithms | (empty) |
//! | `AUTH_ISSUER` | Allowed issuers with optional per-issuer config (see below) | (empty) |
//! | `AUTH_AUDIENCE` | Comma-separated list of allowed JWT audiences | (empty) |
//! | `AUTH_CUSTOM_CLAIM_PREFIX` | Prefix to strip from custom JWT claims | (none) |
//! | `DEFAULT_LOCALE` | Default locale for requests without locale claim | `en` |
//!
//! **`AUTH_ISSUER` syntax:**
//!
//! Issuers can be configured with different validation strategies:
//!
//! ```text
//! # Simple list (all use AUTH_SECRET for validation)
//! AUTH_ISSUER=https://issuer1.com,https://issuer2.com
//!
//! # Per-issuer with shared secret
//! AUTH_ISSUER=https://issuer.com=secret
//!
//! # Per-issuer with JWKS endpoint (relative path appended to issuer URL)
//! AUTH_ISSUER=https://auth.example.com=jwks:/.well-known/jwks.json
//!
//! # Per-issuer with JWKS endpoint (absolute URL)
//! AUTH_ISSUER=https://issuer.com=jwks:https://keys.example.com/jwks.json
//!
//! # Mixed configuration
//! AUTH_ISSUER=https://internal.com=secret,https://external.com=jwks:/.well-known/jwks.json
//! ```
//!
//! ### AWS Services
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `S3_BUCKET_SUFFIX` | Suffix appended to S3 bucket names | (required for S3) |
//! | `DYNAMO_TABLE_PREFIX` | Prefix for DynamoDB table names | (required for DynamoDB) |
//! | `FIREHOSE_STREAM_NAME` | Firehose delivery stream name | normalized `APP_NAME` |
//! | `FIREHOSE_SYSTEM_NAME` | System identifier in Firehose events | normalized `CLUSTER_ID` |
//!
//! ### PostgreSQL
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `POSTGRES_URL` | Connection string | (required for PostgreSQL) |
//! | `POSTGRES_POOL_SIZE` | Maximum pooled connections | `16` |
//! | `POSTGRES_CA_FILE` | PEM bundle of extra trusted CAs (e.g. RDS) | (none) |
//!
//! ### OpenSearch
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `OPENSEARCH_URL` | OpenSearch cluster URL | (required) |
//! | `OPENSEARCH_USER` | OpenSearch username | (empty) |
//! | `OPENSEARCH_PASS` | OpenSearch password | (empty) |
//!
//! ### Observability
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `RUST_LOG` | Console log filter (e.g., `info`, `myapp=debug`) | `info` |
//! | `RUST_TRACE` | OpenTelemetry trace filter | `debug` |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry OTLP endpoint | (required for OTel) |
#![recursion_limit = "256"]
#![deny(
    // Code Quality
    warnings,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    // Safety
    unsafe_code,
    // Robustness
    rust_2018_idioms,
    nonstandard_style,
    future_incompatible,
    // Clippy - Panic Prevention
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Relax some lints for test code
#![cfg_attr(
    test,
    allow(
        unused_results,
        missing_docs,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
use std::env;
use std::sync::LazyLock;

/// Logging and tracing infrastructure.
pub mod logging;

/// General-purpose utilities and helpers.
pub mod tools;

/// HTTP server, authentication, and web utilities.
pub mod web;

/// AWS service integrations (feature-gated).
pub mod aws;

/// OpenSearch/Elasticsearch client.
#[cfg(feature = "open_search")]
pub mod opensearch;

/// Event recording and streaming.
pub mod events;

/// PostgreSQL pool, records and declarative table schemas.
#[cfg(feature = "postgres")]
pub mod postgres;

/// Application name from `APP_NAME` environment variable.
///
/// Used in logging, tracing spans, and service identification.
/// Defaults to `"WASABI"` if not set.
pub static APP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("APP_NAME").unwrap_or("WASABI".to_string()));

/// Application version from `APP_VERSION` environment variable.
///
/// Typically set during CI/CD builds. Defaults to
/// `"DEVELOPMENT-SNAPSHOT-VERSION"` for local development.
pub static APP_VERSION: LazyLock<String> =
    LazyLock::new(|| env::var("APP_VERSION").unwrap_or("DEVELOPMENT-SNAPSHOT-VERSION".to_string()));

/// Cluster identifier from `CLUSTER_ID` environment variable.
///
/// Identifies the deployment cluster or service group.
/// Used in tracing spans and event metadata. Defaults to `"local"`.
pub static CLUSTER_ID: LazyLock<String> =
    LazyLock::new(|| env::var("CLUSTER_ID").unwrap_or("local".to_string()));

/// Task identifier from `TASK_ID` environment variable.
///
/// Identifies the specific task or container instance.
/// Useful for correlating logs across replicas. Defaults to `"local"`.
pub static TASK_ID: LazyLock<String> =
    LazyLock::new(|| env::var("TASK_ID").unwrap_or("local".to_string()));
