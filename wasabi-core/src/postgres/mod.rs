//! PostgreSQL: a connection pool, a thin record layer and declarative table schemas.
//!
//! Three layers, each usable without the next:
//!
//! - [`Database`] — a pooled connection (`deadpool-postgres` over `tokio-postgres`, TLS via
//!   rustls). [`Database::client`] hands out a plain `tokio-postgres` client, so any SQL works.
//! - [`Record`] + [`Table`] — insert / update / upsert / delete / select by column name, built and
//!   bound by `sea-query`. Filters are equality on every given column, joined with `AND`.
//! - [`Table`] as a schema — [`Database::schema_changes`] compares the declaration with the live
//!   database and lists what differs as [`SchemaChange`]s; [`Database::ensure_exists`] applies
//!   every change that cannot lose data and withholds the rest for an operator.
//!
//! # Example
//!
//! ```rust,ignore
//! use wasabi_core::postgres::{Column, ColumnType, Database, Index, Record, Table};
//! use wasabi_core::record;
//!
//! let users = Table::new("users")
//!     .column(Column::new("id", ColumnType::Text).not_null())
//!     .column(Column::new("email", ColumnType::Text).not_null())
//!     .column(Column::new("logins", ColumnType::BigInt).not_null().default_sql("0"))
//!     .primary_key(["id"])
//!     .index(Index::new("by_email", ["email"]).unique());
//!
//! let db = Database::from_env().await?;
//! db.ensure_exists(&users).await?;
//!
//! let client = db.client().await?;
//! users.insert(&client, record! { "id" => "0815", "email" => "a@example.com" }).await?;
//! users.update(&client, record! { "logins" => 1_i64 }, record! { "id" => "0815" }).await?;
//! let row = users.select_one(&client, record! { "id" => "0815" }).await?;
//! ```
//!
//! # Environment Variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `POSTGRES_URL` | Connection string (`postgres://user:pass@host:5432/db?sslmode=require`) | (required) |
//! | `POSTGRES_POOL_SIZE` | Maximum number of pooled connections | `16` |
//! | `POSTGRES_CA_FILE` | PEM file with extra trusted CAs (e.g. the AWS RDS bundle) | (none) |
//!
//! TLS follows the URL's `sslmode`: `disable`, `prefer` (the driver's default — TLS when the server
//! offers it) or `require`. Certificates are always verified, against the platform's trust store
//! plus `POSTGRES_CA_FILE`; RDS certificates chain to Amazon's own roots, which no platform store
//! carries, so an RDS deployment needs the bundle.

mod error;
mod record;
mod schema;
mod table;

pub use error::{Error, Result, retry};
pub use record::Record;
pub use schema::{SchemaChange, SchemaSync};
pub use table::{Column, ColumnType, Index, Table};

/// The pooled client handed out by [`Database::client`].
pub use deadpool_postgres::Client;
/// Implemented by [`Client`] and by transactions, so [`Table`] works inside both.
pub use deadpool_postgres::GenericClient;
/// The exact decimal bound to and read from `NUMERIC` columns ([`ColumnType::Decimal`]).
pub use rust_decimal::Decimal;
/// Statement builder used underneath [`Table`], for queries a [`Record`] filter cannot express.
pub use sea_query;
/// The value type a [`Record`] holds. `Option<T>` converts to a typed `NULL`.
pub use sea_query::Value;
/// The driver, for rows, types and errors.
pub use tokio_postgres;
/// A result row.
pub use tokio_postgres::Row;
/// Wraps a serde type for a `json` / `jsonb` parameter or column read.
pub use tokio_postgres::types::Json;

use anyhow::Context;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sea_query::PostgresQueryBuilder;
use sea_query_postgres::PostgresBinder;
use std::sync::Arc;
use std::time::Duration;
use tokio_postgres_rustls::MakeRustlsConnect;

/// Pool size when `POSTGRES_POOL_SIZE` is unset.
const DEFAULT_POOL_SIZE: usize = 16;

/// How long a caller waits for a free connection, and how long opening one may take. A stuck
/// database must surface as a failed request, not as a request handler that hangs forever.
const POOL_TIMEOUT: Duration = Duration::from_secs(5);

/// Key of the advisory lock that serialises schema changes. Several replicas booting at once all
/// run `ensure_exists`; without the lock two of them race on the same `CREATE TABLE`.
const SCHEMA_LOCK_KEY: i64 = 0x7761_7361_6269; // "wasabi"

/// A pool of connections to one PostgreSQL database.
///
/// Cloning is cheap and shares the pool.
#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pool's config holds the password; only its shape is safe to print.
        let status = self.pool.status();
        f.debug_struct("Database")
            .field("max_size", &status.max_size)
            .field("size", &status.size)
            .finish()
    }
}

impl Database {
    /// Connects using `POSTGRES_URL`, `POSTGRES_POOL_SIZE` and `POSTGRES_CA_FILE`.
    ///
    /// # Errors
    ///
    /// Fails if `POSTGRES_URL` is unset or malformed, a CA file cannot be read, or the database
    /// does not answer — the pool is probed once, so a wrong password fails the boot, not the
    /// first request.
    pub async fn from_env() -> anyhow::Result<Database> {
        tracing::info!("Setting up PostgreSQL....");

        let url =
            std::env::var("POSTGRES_URL").context("No POSTGRES_URL provided in environment")?;
        let pool_size = match std::env::var("POSTGRES_POOL_SIZE") {
            Ok(value) => value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("POSTGRES_POOL_SIZE='{value}' is not a number"))?,
            Err(_) => DEFAULT_POOL_SIZE,
        };
        let ca_file = std::env::var("POSTGRES_CA_FILE")
            .ok()
            .filter(|path| !path.trim().is_empty());

        Database::connect(&url, pool_size, ca_file.as_deref()).await
    }

    /// Connects to `url` with at most `pool_size` connections, trusting the platform's CAs plus
    /// those in `ca_file`.
    ///
    /// # Errors
    ///
    /// Fails if the URL is malformed, the CA file is unreadable, or the database does not answer.
    pub async fn connect(
        url: &str,
        pool_size: usize,
        ca_file: Option<&str>,
    ) -> anyhow::Result<Database> {
        let pg_config: tokio_postgres::Config = url
            .parse()
            .context("POSTGRES_URL is not a valid connection string")?;

        let manager = Manager::from_config(
            pg_config,
            tls_connector(ca_file)?,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_size.max(1))
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(POOL_TIMEOUT))
            .create_timeout(Some(POOL_TIMEOUT))
            .recycle_timeout(Some(POOL_TIMEOUT))
            .build()
            .context("Failed to build the PostgreSQL pool")?;

        let database = Database { pool };
        let client = database.client().await?;
        let _ = client
            .query_one("SELECT 1", &[])
            .await
            .context("PostgreSQL did not answer")?;

        Ok(database)
    }

    /// Takes a connection from the pool. It returns to the pool when dropped.
    ///
    /// # Errors
    ///
    /// Fails if no connection frees up or opens within five seconds.
    pub async fn client(&self) -> Result<Client> {
        self.pool.get().await.map_err(|err| {
            Error::Other(anyhow::Error::new(err).context("No PostgreSQL connection available"))
        })
    }

    /// Lists what it takes to bring the database in line with `table`, without changing anything.
    ///
    /// # Errors
    ///
    /// Fails if the catalog cannot be read.
    pub async fn schema_changes(&self, table: &Table) -> Result<Vec<SchemaChange>> {
        let client = self.client().await?;
        let existing = schema::introspect(&client, table.name()).await?;
        Ok(schema::diff(table, existing.as_ref()))
    }

    /// Creates `table` or migrates it towards its declaration, applying every change that cannot
    /// lose data.
    ///
    /// Changes that may lose data — dropping a column, narrowing a type — are *withheld*: logged
    /// on `WARN` with their SQL and returned, so an operator can run them deliberately through
    /// [`Database::apply`]. Everything happens in one transaction under an advisory lock, so
    /// concurrently booting replicas apply each change once and a failed change applies none.
    ///
    /// # Errors
    ///
    /// Fails if the catalog cannot be read or a change is rejected — e.g. `SET NOT NULL` on a
    /// column that still holds `NULL`s.
    pub async fn ensure_exists(&self, table: &Table) -> Result<SchemaSync> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|err| Error::from_driver(err, "Failed to start a schema transaction"))?;
        let _ = transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK_KEY])
            .await
            .map_err(|err| Error::from_driver(err, "Failed to take the schema lock"))?;

        let existing = schema::introspect(&transaction, table.name()).await?;
        let (withheld, applied): (Vec<_>, Vec<_>) = schema::diff(table, existing.as_ref())
            .into_iter()
            .partition(|change| change.data_loss_expected);

        for change in &applied {
            tracing::info!(table = table.name(), sql = change.sql, "{}", change.label);
            transaction
                .batch_execute(&change.sql)
                .await
                .map_err(|err| {
                    Error::from_driver(err, format!("Schema change failed: {}", change.label))
                })?;
        }
        transaction.commit().await.map_err(|err| {
            Error::from_driver(
                err,
                format!("Failed to commit schema changes for '{}'", table.name()),
            )
        })?;

        for change in &withheld {
            tracing::warn!(
                table = table.name(),
                sql = change.sql,
                "Withheld a schema change that may lose data: {}",
                change.label
            );
        }

        Ok(SchemaSync { applied, withheld })
    }

    /// Applies `changes` in order, in one transaction — including those that may lose data.
    ///
    /// # Errors
    ///
    /// Fails, and applies nothing, if any change is rejected.
    pub async fn apply(&self, changes: &[SchemaChange]) -> Result<()> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|err| Error::from_driver(err, "Failed to start a schema transaction"))?;
        let _ = transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK_KEY])
            .await
            .map_err(|err| Error::from_driver(err, "Failed to take the schema lock"))?;
        for change in changes {
            tracing::info!(sql = change.sql, "{}", change.label);
            transaction
                .batch_execute(&change.sql)
                .await
                .map_err(|err| {
                    Error::from_driver(err, format!("Schema change failed: {}", change.label))
                })?;
        }
        transaction
            .commit()
            .await
            .map_err(|err| Error::from_driver(err, "Failed to commit schema changes"))
    }
}

/// Runs a `sea-query` statement that returns rows.
///
/// # Errors
///
/// Fails if the database rejects the statement, classified as [`Error`].
pub async fn fetch<C, S>(client: &C, statement: &S) -> Result<Vec<Row>>
where
    C: GenericClient + Sync,
    S: PostgresBinder,
{
    let (sql, values) = statement.build_postgres(PostgresQueryBuilder);
    client
        .query(sql.as_str(), &values.as_params())
        .await
        .map_err(|err| Error::from_driver(err, format!("Query failed: {sql}")))
}

/// Runs a `sea-query` statement and returns the number of affected rows.
///
/// # Errors
///
/// Fails if the database rejects the statement.
pub async fn execute<C, S>(client: &C, statement: &S) -> Result<u64>
where
    C: GenericClient + Sync,
    S: PostgresBinder,
{
    let (sql, values) = statement.build_postgres(PostgresQueryBuilder);
    client
        .execute(sql.as_str(), &values.as_params())
        .await
        .map_err(|err| Error::from_driver(err, format!("Statement failed: {sql}")))
}

/// Builds the TLS connector: aws-lc-rs, the platform's roots plus an optional PEM bundle.
fn tls_connector(ca_file: Option<&str>) -> anyhow::Result<MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore::empty();

    // A platform store with one unreadable certificate still yields the rest; only an empty
    // result is worth a word, and even that is fine when POSTGRES_CA_FILE supplies the roots.
    let native = rustls_native_certs::load_native_certs();
    let (_, ignored) = roots.add_parsable_certificates(native.certs);
    if ignored > 0 {
        tracing::debug!("Ignored {ignored} unparsable platform certificates");
    }

    if let Some(path) = ca_file {
        let certificates = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("Cannot read POSTGRES_CA_FILE '{path}'"))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("POSTGRES_CA_FILE '{path}' is not a PEM bundle"))?;
        for certificate in certificates {
            roots
                .add(certificate)
                .with_context(|| format!("POSTGRES_CA_FILE '{path}' holds an invalid CA"))?;
        }
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("Failed to set up TLS for PostgreSQL")?
    .with_root_certificates(roots)
    .with_no_client_auth();

    Ok(MakeRustlsConnect::new(config))
}

/// Test support: a database for integration tests, or `None` to skip them.
#[cfg(test)]
pub(crate) mod test {
    use super::Database;

    /// Connects to `POSTGRES_TEST_URL`; `None` when it is unset, so `cargo test` stays green on
    /// a machine without a database.
    pub async fn database() -> Option<Database> {
        let url = std::env::var("POSTGRES_TEST_URL").ok()?;
        Some(
            Database::connect(&url, 4, None)
                .await
                .expect("POSTGRES_TEST_URL is set but unreachable"),
        )
    }

    /// A table name no other test run uses.
    pub fn unique_table(name: &str) -> String {
        format!("{name}_{}", rand::random::<u32>())
    }
}
