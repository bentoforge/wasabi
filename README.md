# Wasabi

A lightweight Rust microservices framework for containerized deployments.

Wasabi provides the building blocks for creating robust, observable web services with minimal boilerplate. It's designed for AWS-centric deployments but works anywhere you can run containers.

## Project Structure

Wasabi is organized as a Cargo workspace with three crates:

```
wasabi/
├── Cargo.toml          # Workspace root, re-exports both crates
├── src/lib.rs          # Re-exports wasabi-core and wasabi-macro
├── wasabi-core/        # Core framework functionality
│   └── src/
│       ├── lib.rs
│       ├── logging/    # Tracing and OpenTelemetry
│       ├── web/        # HTTP server, auth, filters
│       ├── aws/        # S3, DynamoDB, Bedrock
│       ├── events/     # Event recording (Firehose)
│       └── tools/      # Utilities (ID generation, i18n, etc.)
└── wasabi-macro/       # Procedural macros
    └── src/lib.rs      # Event derive macro
```

### Crate Roles

| Crate | Purpose |
|-------|---------|
| `wasabi` | Facade crate - re-exports everything, this is what you depend on |
| `wasabi-core` | Core functionality: web server, auth, AWS integrations, logging |
| `wasabi-macro` | Procedural macros (`#[derive(Event)]`) |

**Usage:** Add `wasabi` as your dependency. It re-exports both `wasabi-core` and `wasabi-macro`:

```toml
[dependencies]
wasabi = { path = "../wasabi", features = ["aws_dynamodb", "aws_firehose"] }
```

## Quick Start

```rust
use wasabi::web::warp::run_webserver;
use wasabi::logging;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::setup_tracing();

    let routes = warp::path("health").map(|| "OK");
    run_webserver(routes).await
}
```

## Feature Flags

All integrations are opt-in to keep compile times fast. Enable only what you need:

| Feature | Description | Key Dependencies |
|---------|-------------|------------------|
| `pretty_logs` | Colorful console output for local development | `nu-ansi-term` |
| `open_telemetry` | Distributed tracing export to OTLP collectors | `opentelemetry`, `tracing-opentelemetry` |
| `aws_s3` | S3 client with ETag-based caching, multipart uploads | `aws-sdk-s3` |
| `aws_dynamodb` | DynamoDB client with table prefix support | `aws-sdk-dynamodb`, `serde_dynamo` |
| `aws_firehose` | Event streaming to Kinesis Firehose | `aws-sdk-firehose` |
| `aws_bedrock` | AI model integration with SSE streaming | `aws-sdk-bedrockruntime` |
| `open_search` | OpenSearch/Elasticsearch client | `opensearch` |

Example with multiple features:

```toml
[dependencies]
wasabi = { path = "../wasabi", features = ["pretty_logs", "aws_s3", "aws_dynamodb"] }
```

## Core Modules

### Web (`wasabi::web`)

Built on [Warp](https://github.com/seanmonstar/warp) with additional filters:

- **Authentication** - JWT validation with multiple issuer support (shared secrets or JWKS)
- **Body parsing** - JSON, form data, streaming with size limits
- **Error handling** - `ApiError` type with HTTP status mapping

### AWS Integrations (`wasabi::aws`)

- **S3** - Bucket naming with suffix support, `CachedObject` trait for ETag-based caching
- **DynamoDB** - Table prefix support, schema helpers, pagination utilities
- **Bedrock** - Streaming AI responses as Server-Sent Events

### Events (`wasabi::events`)

Event recording with the `Event` trait and Firehose backend:

```rust
use wasabi::Event;

#[derive(Event, serde::Serialize)]
#[event(name = "user.signup")]
struct UserSignup {
    user_id: String,
    email: String,
}
```

### Logging (`wasabi::logging`)

Unified tracing setup with optional OpenTelemetry export:

```rust
wasabi::logging::setup_tracing();  // Reads RUST_LOG, RUST_TRACE env vars
```

## Environment Variables

### Core

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_NAME` | Application identifier | `WASABI` |
| `APP_VERSION` | Version string | `DEVELOPMENT-SNAPSHOT-VERSION` |
| `CLUSTER_ID` | Cluster/service identifier | `local` |
| `TASK_ID` | Task/instance identifier | `local` |
| `BIND_ADDRESS` | HTTP server bind address | (required) |

### Authentication

| Variable | Description |
|----------|-------------|
| `AUTH_SECRET` | JWT shared secret for HMAC validation |
| `AUTH_ALGORITHMS` | Comma-separated allowed JWT algorithms |
| `AUTH_ISSUER` | Allowed issuers (see syntax below) |
| `AUTH_AUDIENCE` | Comma-separated allowed audiences |
| `AUTH_CUSTOM_CLAIM_PREFIX` | Prefix to strip from custom claims |
| `DEFAULT_LOCALE` | Default locale for requests |
| `GITHUB_OIDC_ALLOWED_REPOS` | Regex for allowed GitHub repos (e.g., `myorg/.*`) |
| `GITHUB_OIDC_CLAIM_MAPPING` | Claim transformation rules (e.g., `tenant=ci,permissions=[deploy]`) |

**`AUTH_ISSUER` syntax:**

```bash
# Simple list (all use AUTH_SECRET)
AUTH_ISSUER=https://issuer1.com,https://issuer2.com

# Per-issuer with shared secret
AUTH_ISSUER=https://issuer.com=mysecret

# Per-issuer with JWKS (relative path)
AUTH_ISSUER=https://auth.example.com=jwks:/.well-known/jwks.json

# Per-issuer with JWKS (absolute URL)
AUTH_ISSUER=https://issuer.com=jwks:https://keys.example.com/jwks.json

# Mixed
AUTH_ISSUER=https://internal.com=secret123,https://external.com=jwks:/.well-known/jwks.json
```

### AWS Services

| Variable | Description |
|----------|-------------|
| `S3_BUCKET_SUFFIX` | Suffix for bucket names (e.g., `prod.example.com`) |
| `DYNAMO_TABLE_PREFIX` | Prefix for table names (e.g., `myapp-prod`) |
| `FIREHOSE_STREAM_NAME` | Firehose delivery stream name |

### Observability

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Console log filter | `info` |
| `RUST_TRACE` | OpenTelemetry trace filter | `debug` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | (required for OTel) |
| `LOG_CONNECTION_ERRORS` | Log connections a peer tore down (`IncompleteMessage`, resets, broken pipes), which warp reports at `ERROR` | `false` |

## Development

```bash
# Build with all features
cargo build --all-features

# Run tests
cargo test --all-features

# Format code
cargo fmt --all

# Lint
cargo clippy --all-features -- -D warnings
```

## License

This project is licensed under the **MIT License**.
