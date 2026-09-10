# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wasabi is a lightweight Rust microservices framework for containerized deployments. It's organized as a Cargo workspace with three crates:
- **wasabi** (root) - Re-exports from both crates
- **wasabi-core** - Core framework functionality
- **wasabi-macro** - Procedural macros (Event derive)

Project language (code, commit messages, documentation) is english.

## Build Commands

```bash
# Build
cargo build --all-features

# Run tests
cargo test --all-features

# Format code
cargo fmt --all

# Lint (warnings are errors in CI)
cargo clippy --all-features -- -D warnings

# Security audit
cargo audit
```

## Feature Flags

All features are opt-in. Enable as needed:
- `pretty_logs` - Colorful console output for OpenTelemetry spans
- `open_telemetry` - OpenTelemetry tracing setup
- `aws_s3` - S3 client with caching and multipart upload
- `aws_dynamodb` - DynamoDB integration
- `aws_firehose` - AWS Firehose event recording
- `aws_bedrock` - AWS Bedrock AI integration
- `open_search` - AWS OpenSearch integration

## Architecture

### Web Layer (`wasabi-core/src/web/`)
- Built on **Warp** framework with filter combinators
- `auth/` - JWT authentication supporting multiple issuers (JWKS URL or shared secret)
- `warp.rs` - Custom filters for body parsing, streaming, error handling
- `ApiError` type maps errors to HTTP status codes

### AWS Integrations (`wasabi-core/src/aws/`)
- Feature-gated modules to avoid bloat
- `s3.rs` - S3 client with ETag-based caching (`CachedS3Object` trait)
- `dynamodb/` - DynamoDB with schema support
- `bedrock.rs` - AI model integration

### Observability (`wasabi-core/src/logging/`)
- Tracing with optional OpenTelemetry export
- `pretty.rs` - Development-friendly console output

### Events (`wasabi-core/src/events/`)
- `Event` trait (derived via macro) for custom event types
- `EventRecorder` trait with Firehose implementation

## Key Patterns

**Error Handling**: Chain context with `anyhow::Context`, convert to `ApiError` via `ResultExt::map_err_to_http()`.
Failures are reported in exactly one place: `handle_rejection` (installed by `run_webserver`) logs a
5xx on `ERROR` with the full context chain and a 4xx on `DEBUG`. Services must not log failures on
their way out — that is what turns one broken request into one log line instead of five.

**Tracing**: `#[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]` on
service and repository functions, `#[tracing::instrument(name = "GET /thing/v1", skip_all)]` on route
handlers. Always pin `err` to `debug`: it defaults to `Level::ERROR` regardless of the span's level,
so an unpinned `err` reports a caller's malformed request as loudly as a broken database — and does
so once per instrumented function along the call chain. Pinned, the trace still shows exactly which
function failed (`RUST_TRACE=debug`) while the container log stays quiet unless something is really
broken — `handle_rejection` still reports every 5xx. Only boot and setup code (`with_client`,
`from_env`, `install`) belongs on `info`.

**Async**: Everything is async/await with Tokio runtime. Use `#[tokio::test]` for async tests.

## Environment Variables

- `APP_NAME`, `APP_VERSION` - Application metadata
- `BIND_ADDRESS` - HTTP server address (required)
- `AUTH_SECRET`, `AUTH_ALGORITHMS`, `AUTH_ISSUER`, `AUTH_AUDIENCE` - JWT configuration
- `AUTH_CUSTOM_CLAIM_PREFIX` - Custom JWT claim prefix
