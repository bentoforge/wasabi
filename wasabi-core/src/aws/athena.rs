//! Athena client for querying a Glue-catalogued data lake.
//!
//! Athena is not a database: a query is started, polled until it finishes, and its rows are then
//! read back in pages — seconds of wall clock, billed per scanned byte. This module wraps that
//! sequence into one call and adds the two things every caller ends up needing anyway:
//!
//! - **Parameters instead of string interpolation** ([`Query::bind`]). A tenant id spliced into SQL
//!   is an injection in a query whose whole job is to not cross a tenant boundary.
//! - **A result cache** ([`QueryCache`]). Aggregates that a nightly ETL rebuilds do not change
//!   between runs, so asking Athena twice costs money and seconds for an identical answer.
//!
//! # Environment Variables
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `ATHENA_WORKGROUP` | Workgroup to run in (required) |
//! | `ATHENA_DATABASE` | Default Glue database for unqualified table names (required) |
//! | `ATHENA_CATALOG` | Data catalog; defaults to `AwsDataCatalog` |
//! | `ATHENA_OUTPUT_LOCATION` | `s3://…` for results; omit when the workgroup enforces its own |
//! | `ATHENA_QUERY_TIMEOUT_SECONDS` | How long to wait for a query; defaults to 30 |
//!
//! A workgroup created with `enforce_workgroup_configuration` already carries an output location
//! and overrides whatever a client sends, which is why `ATHENA_OUTPUT_LOCATION` is optional. Pair
//! that with the workgroup's `bytes_scanned_cutoff_per_query`: it is the only bound that stops a
//! query which lost its partition filter, and no client-side timeout can replace it.
//!
//! # Usage
//!
//! ```rust,ignore
//! let athena = AthenaClient::from_env()
//!     .await?
//!     .with_cache(Arc::new(InProcessQueryCache::new(256)));
//!
//! let query = Query::new(
//!     "SELECT supplier_item_number, sum(num_calls) AS calls
//!        FROM process_product_daily
//!       WHERE supplier_tenant_id = ? AND event_date BETWEEN ? AND ?
//!       GROUP BY supplier_item_number",
//! )
//! .bind(tenant_id)
//! .bind(from)
//! .bind(to);
//!
//! let result = athena.query_cached(&query, Duration::from_secs(3600)).await?;
//! for row in result.rows() {
//!     println!("{} {}", row.get_str("supplier_item_number")?, row.get_i64("calls")?);
//! }
//! ```

use anyhow::{Context, bail};
use async_trait::async_trait;
use aws_sdk_athena::Client;
use aws_sdk_athena::types::{
    QueryExecutionContext, QueryExecutionState, ResultConfiguration, ResultSet as AwsResultSet,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

// Same swap as `web::auth::jwks`: the cache's expiry is clock arithmetic, and a test that has to
// sleep through it is a test nobody runs. Tokio's own test clock would need its `test-util`
// feature, which this crate does not carry.
#[cfg(test)]
use mock_instant::global::Instant;
#[cfg(not(test))]
use tokio::time::Instant;

/// Catalog used when `ATHENA_CATALOG` is unset.
const DEFAULT_CATALOG: &str = "AwsDataCatalog";

/// How long to wait for a query before giving up and cancelling it.
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// First poll interval. Short, because a query over small partitioned aggregates often finishes
/// within a second and the dashboard waiting for it is a page load.
const POLL_INTERVAL_MIN: Duration = Duration::from_millis(150);

/// Longest poll interval. The backoff doubles up to this, so a slow query costs a handful of
/// `GetQueryExecution` calls rather than hundreds.
const POLL_INTERVAL_MAX: Duration = Duration::from_millis(2_000);

/// Rows per `GetQueryResults` page. 1000 is the service maximum.
const RESULTS_PAGE_SIZE: i32 = 1_000;

/// A SQL statement plus the values bound to its `?` placeholders.
///
/// Athena's execution parameters are positional and always travel as strings; the engine casts them
/// against the column they are compared to. They work in value positions — `WHERE`, `HAVING`,
/// `VALUES` — and **not** for identifiers: a table or column name cannot be parameterised, so those
/// have to be fixed in the SQL itself.
#[derive(Clone, Debug)]
pub struct Query {
    sql: String,
    parameters: Vec<String>,
}

impl Query {
    /// Creates a query from SQL, using `?` for every value that comes from outside.
    pub fn new(sql: impl Into<String>) -> Self {
        Query {
            sql: sql.into(),
            parameters: Vec::new(),
        }
    }

    /// Binds the next `?`, in order.
    #[must_use]
    pub fn bind(mut self, value: impl Display) -> Self {
        self.parameters.push(value.to_string());
        self
    }

    /// The SQL as it will be sent.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// The bound values, in the order they were bound.
    pub fn parameters(&self) -> &[String] {
        &self.parameters
    }

    /// A key identifying this exact query and parameter set.
    ///
    /// Plain text rather than a digest: wasabi has no hash dependency, a cache that needs a bounded
    /// key (DynamoDB, Redis) will hash it with whatever it already uses, and an in-process map is
    /// happy with the string. The parameters are part of it, or one tenant would be served
    /// another's rows.
    ///
    /// Each part is prefixed with its byte length rather than joined by a separator. A parameter
    /// comes from outside — a JWT claim, a query string — so it can contain any byte a separator
    /// might use, and then two different queries would share one key. Length prefixes cannot be
    /// forged that way: the encoding is unambiguous whatever the values contain.
    pub fn cache_key(&self, database: &str) -> String {
        let mut key = String::with_capacity(self.sql.len() + 64);
        push_part(&mut key, database);
        push_part(&mut key, &self.sql);
        for parameter in &self.parameters {
            push_part(&mut key, parameter);
        }
        key
    }
}

/// Appends one length-prefixed part to a cache key.
fn push_part(key: &mut String, part: &str) {
    use std::fmt::Write;

    // Writing to a String cannot fail.
    let _ = write!(key, "{}:{}", part.len(), part);
}

/// One column of a result set, as Athena described it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// Column name or alias.
    pub name: String,
    /// Athena type name (`varchar`, `bigint`, `double`, `boolean`, …).
    pub type_name: String,
}

/// One row, with the column names it was selected under.
///
/// `values` always has exactly one entry per column — [`append_rows`] pads a short page row and
/// drops a long one, so every accessor here can look a column up by index without a bounds worry.
#[derive(Clone, Debug)]
pub struct Row {
    columns: Arc<Vec<Column>>,
    values: Vec<Option<String>>,
}

impl Row {
    fn index_of(&self, column: &str) -> anyhow::Result<usize> {
        self.columns
            .iter()
            .position(|candidate| candidate.name == column)
            .with_context(|| {
                format!(
                    "No column '{}' in the result; it has: {}",
                    column,
                    self.columns
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// The raw value, or `None` for SQL `NULL`.
    pub fn get_opt_str(&self, column: &str) -> anyhow::Result<Option<&str>> {
        let index = self.index_of(column)?;
        Ok(self.values.get(index).and_then(|value| value.as_deref()))
    }

    /// The value as text. Fails on `NULL` — use [`Self::get_opt_str`] where a column is nullable.
    pub fn get_str(&self, column: &str) -> anyhow::Result<&str> {
        self.get_opt_str(column)?
            .with_context(|| format!("Column '{}' is null", column))
    }

    /// The value as an integer.
    pub fn get_i64(&self, column: &str) -> anyhow::Result<i64> {
        self.get_str(column)?
            .parse()
            .with_context(|| format!("Column '{}' is not an integer", column))
    }

    /// The value as a float.
    pub fn get_f64(&self, column: &str) -> anyhow::Result<f64> {
        self.get_str(column)?
            .parse()
            .with_context(|| format!("Column '{}' is not a number", column))
    }

    /// The value as a boolean.
    pub fn get_bool(&self, column: &str) -> anyhow::Result<bool> {
        self.get_str(column)?
            .parse()
            .with_context(|| format!("Column '{}' is not a boolean", column))
    }

    /// The row as a JSON object, numbers and booleans coerced by the column's Athena type.
    ///
    /// Athena hands every value back as text; without the coercion a `bigint` would deserialize
    /// into a `String` field and nothing else.
    pub fn to_json(&self) -> Value {
        let mut object = Map::with_capacity(self.columns.len());
        for (column, value) in self.columns.iter().zip(&self.values) {
            let _ = object.insert(
                column.name.clone(),
                coerce(&column.type_name, value.as_deref()),
            );
        }
        Value::Object(object)
    }
}

/// Turns one Athena value into JSON, following the column's declared type.
///
/// A value that does not parse as its own type is kept as text rather than dropped: a caller
/// deserializing into a typed struct gets a clear serde error naming the field, which beats a
/// silent `null`.
fn coerce(type_name: &str, value: Option<&str>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };

    match type_name {
        "tinyint" | "smallint" | "integer" | "int" | "bigint" => value
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::from(value)),
        "double" | "float" | "real" | "decimal" => value
            .parse::<f64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::from(value)),
        "boolean" => value
            .parse::<bool>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::from(value)),
        _ => Value::from(value),
    }
}

/// The answer to one query.
#[derive(Clone, Debug)]
pub struct ResultSet {
    columns: Arc<Vec<Column>>,
    rows: Vec<Row>,
    /// Bytes Athena scanned. This is what the query cost; log it, or a lost partition filter stays
    /// invisible until the bill arrives.
    pub scanned_bytes: i64,
    /// Athena's id for the execution, for correlating with the service's own logs.
    pub execution_id: String,
}

impl ResultSet {
    /// The columns, in select order.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The rows, header row already removed.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// Whether the query matched nothing.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Deserializes every row into `T`, by column name.
    pub fn rows_as<T: DeserializeOwned>(&self) -> anyhow::Result<Vec<T>> {
        self.rows
            .iter()
            .map(|row| serde_json::from_value(row.to_json()).context("Failed to map a result row"))
            .collect()
    }
}

/// A place to keep query results between calls.
///
/// Implemented in-process by [`InProcessQueryCache`]. A service that runs on more than one node and
/// minds paying per node can back it with something shared — the trait exists so that choice is the
/// service's, not wasabi's: a shared cache means a store, and not every consumer wants one.
#[async_trait]
pub trait QueryCache: Send + Sync {
    /// Returns a still-valid entry, or `None`.
    async fn get(&self, key: &str) -> Option<Arc<ResultSet>>;

    /// Stores an entry, valid for `valid_for` from now.
    async fn put(&self, key: &str, value: Arc<ResultSet>, valid_for: Duration);
}

/// Entry of the in-process cache.
struct CacheEntry {
    value: Arc<ResultSet>,
    expires_at: Instant,
}

/// A bounded, per-process result cache.
///
/// Good enough wherever the underlying data is immutable between ETL runs: every node computes the
/// same answer, so the cost of not sharing is one miss per node per query, never a wrong number.
/// What it does not do is coalesce concurrent identical queries — the first burst after an ETL run
/// can still send the same query several times. That is a bounded, measurable cost, so it is left
/// until someone measures it.
pub struct InProcessQueryCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    capacity: usize,
}

impl InProcessQueryCache {
    /// Creates a cache holding at most `capacity` results.
    ///
    /// A result set is held whole in memory, so the bound is on entries and the caller picks it
    /// knowing how wide its queries are.
    pub fn new(capacity: usize) -> Self {
        InProcessQueryCache {
            entries: RwLock::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Drops what has expired, then — if still full — whatever expires soonest.
    fn make_room(entries: &mut HashMap<String, CacheEntry>, capacity: usize) {
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);

        while entries.len() >= capacity {
            let Some(soonest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            let _ = entries.remove(&soonest);
        }
    }
}

#[async_trait]
impl QueryCache for InProcessQueryCache {
    async fn get(&self, key: &str) -> Option<Arc<ResultSet>> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.value.clone())
    }

    async fn put(&self, key: &str, value: Arc<ResultSet>, valid_for: Duration) {
        let mut entries = self.entries.write().await;
        Self::make_room(&mut entries, self.capacity);
        let _ = entries.insert(
            key.to_owned(),
            CacheEntry {
                value,
                expires_at: Instant::now() + valid_for,
            },
        );
    }
}

/// Athena client bound to one workgroup and one default database.
#[derive(Clone)]
pub struct AthenaClient {
    /// The underlying AWS SDK Athena client.
    pub client: Client,
    workgroup: String,
    database: String,
    catalog: String,
    output_location: Option<String>,
    query_timeout: Duration,
    cache: Option<Arc<dyn QueryCache>>,
}

impl AthenaClient {
    /// Creates a client from environment configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `ATHENA_WORKGROUP` or `ATHENA_DATABASE` is not set.
    #[tracing::instrument(level = "info", err(Display))]
    pub async fn from_env() -> anyhow::Result<AthenaClient> {
        tracing::info!("Setting up Athena....");

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;

        let query_timeout = match env::var("ATHENA_QUERY_TIMEOUT_SECONDS") {
            Ok(value) => Duration::from_secs(
                value
                    .parse()
                    .context("ATHENA_QUERY_TIMEOUT_SECONDS is not a number of seconds")?,
            ),
            Err(_) => DEFAULT_QUERY_TIMEOUT,
        };

        Ok(AthenaClient {
            client: Client::new(&config),
            workgroup: env::var("ATHENA_WORKGROUP")
                .context("No ATHENA_WORKGROUP provided in environment")?,
            database: env::var("ATHENA_DATABASE")
                .context("No ATHENA_DATABASE provided in environment")?,
            catalog: env::var("ATHENA_CATALOG").unwrap_or_else(|_| DEFAULT_CATALOG.to_owned()),
            output_location: env::var("ATHENA_OUTPUT_LOCATION").ok(),
            query_timeout,
            cache: None,
        })
    }

    /// Attaches a result cache, used by [`Self::query_cached`].
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<dyn QueryCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The default database queries run against.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Runs a query and returns all of its rows.
    #[tracing::instrument(level = "debug", skip(self, query), fields(sql = %query.sql), err(level = "debug", Display))]
    pub async fn query(&self, query: &Query) -> anyhow::Result<Arc<ResultSet>> {
        let execution_id = self.start(query).await?;
        let scanned_bytes = self.await_completion(&execution_id).await?;
        let result = self.collect_results(&execution_id, scanned_bytes).await?;

        tracing::debug!(
            execution_id = %execution_id,
            rows = result.rows.len(),
            scanned_bytes,
            "Athena query finished"
        );

        Ok(Arc::new(result))
    }

    /// Like [`Self::query`], but serves a cached answer when one is still valid.
    ///
    /// `valid_for` is the caller's statement about its own data, not a guess this module could
    /// make. For aggregates rebuilt by a nightly job, the honest value is the time left until the
    /// next run — a fixed hour would let a dashboard go cold in the middle of the day for nothing.
    ///
    /// Without a cache attached this is just [`Self::query`].
    #[tracing::instrument(level = "debug", skip(self, query), fields(sql = %query.sql), err(level = "debug", Display))]
    pub async fn query_cached(
        &self,
        query: &Query,
        valid_for: Duration,
    ) -> anyhow::Result<Arc<ResultSet>> {
        let Some(cache) = &self.cache else {
            return self.query(query).await;
        };

        let key = query.cache_key(&self.database);
        if let Some(hit) = cache.get(&key).await {
            tracing::debug!(rows = hit.rows.len(), "Athena query served from cache");
            return Ok(hit);
        }

        let result = self.query(query).await?;
        cache.put(&key, result.clone(), valid_for).await;

        Ok(result)
    }

    /// Submits the query and returns its execution id.
    #[tracing::instrument(level = "debug", skip_all, err(level = "debug", Display))]
    async fn start(&self, query: &Query) -> anyhow::Result<String> {
        let mut request = self
            .client
            .start_query_execution()
            .query_string(&query.sql)
            .work_group(&self.workgroup)
            .query_execution_context(
                QueryExecutionContext::builder()
                    .database(&self.database)
                    .catalog(&self.catalog)
                    .build(),
            );

        if !query.parameters.is_empty() {
            request = request.set_execution_parameters(Some(query.parameters.clone()));
        }

        // A workgroup with `enforce_workgroup_configuration` ignores this anyway; sending it only
        // matters for one that does not carry its own location.
        if let Some(output_location) = &self.output_location {
            request = request.result_configuration(
                ResultConfiguration::builder()
                    .output_location(output_location)
                    .build(),
            );
        }

        let response = request
            .send()
            .await
            .context("Failed to start the Athena query")?;

        response
            .query_execution_id
            .context("Athena accepted the query but returned no execution id")
    }

    /// Polls until the query finishes, and returns the bytes it scanned.
    ///
    /// On timeout the execution is cancelled rather than abandoned: an Athena query goes on
    /// scanning — and billing — after the client that asked for it has stopped listening.
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn await_completion(&self, execution_id: &str) -> anyhow::Result<i64> {
        let deadline = Instant::now() + self.query_timeout;
        let mut interval = POLL_INTERVAL_MIN;

        loop {
            let execution = self
                .client
                .get_query_execution()
                .query_execution_id(execution_id)
                .send()
                .await
                .context("Failed to ask Athena how the query is doing")?
                .query_execution
                .context("Athena reported no execution for the id it just issued")?;

            let status = execution
                .status
                .context("Athena reported an execution without a status")?;

            match status.state {
                Some(QueryExecutionState::Succeeded) => {
                    return Ok(execution
                        .statistics
                        .and_then(|statistics| statistics.data_scanned_in_bytes)
                        .unwrap_or_default());
                }
                Some(QueryExecutionState::Failed) | Some(QueryExecutionState::Cancelled) => {
                    bail!(
                        "The Athena query {}: {}",
                        status
                            .state
                            .map(|state| state.as_str().to_lowercase())
                            .unwrap_or_else(|| "failed".to_owned()),
                        status
                            .state_change_reason
                            .unwrap_or_else(|| "no reason given".to_owned())
                    );
                }
                _ => {}
            }

            if Instant::now() >= deadline {
                self.cancel(execution_id).await;
                bail!(
                    "The Athena query did not finish within {:?}",
                    self.query_timeout
                );
            }

            sleep(interval).await;
            interval = (interval * 2).min(POLL_INTERVAL_MAX);
        }
    }

    /// Stops a running execution. Best effort: the query is already past saving, and failing to
    /// cancel it must not replace the timeout the caller needs to see.
    async fn cancel(&self, execution_id: &str) {
        if let Err(err) = self
            .client
            .stop_query_execution()
            .query_execution_id(execution_id)
            .send()
            .await
        {
            tracing::warn!(
                execution_id = %execution_id,
                error = %err,
                "Could not cancel the timed-out Athena query; it may keep scanning"
            );
        }
    }

    /// Reads every page of results.
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn collect_results(
        &self,
        execution_id: &str,
        scanned_bytes: i64,
    ) -> anyhow::Result<ResultSet> {
        let mut columns: Option<Arc<Vec<Column>>> = None;
        let mut rows: Vec<Row> = Vec::new();
        let mut next_token: Option<String> = None;
        let mut first_page = true;

        loop {
            let response = self
                .client
                .get_query_results()
                .query_execution_id(execution_id)
                .max_results(RESULTS_PAGE_SIZE)
                .set_next_token(next_token.clone())
                .send()
                .await
                .context("Failed to read the Athena query results")?;

            let result_set = response
                .result_set
                .context("Athena returned a results page without a result set")?;

            let page_columns = match &columns {
                Some(columns) => columns.clone(),
                None => {
                    let parsed = Arc::new(columns_of(&result_set)?);
                    columns = Some(parsed.clone());
                    parsed
                }
            };

            append_rows(&result_set, &page_columns, first_page, &mut rows);

            first_page = false;
            next_token = response.next_token;
            if next_token.is_none() {
                break;
            }
        }

        Ok(ResultSet {
            columns: columns.unwrap_or_default(),
            rows,
            scanned_bytes,
            execution_id: execution_id.to_owned(),
        })
    }
}

/// Reads the column descriptions of a results page.
fn columns_of(result_set: &AwsResultSet) -> anyhow::Result<Vec<Column>> {
    let metadata = result_set
        .result_set_metadata
        .as_ref()
        .context("Athena returned results without column metadata")?;

    Ok(metadata
        .column_info()
        .iter()
        .map(|info| Column {
            name: info.name().to_owned(),
            type_name: info.r#type().to_owned(),
        })
        .collect())
}

/// Appends a page's rows, dropping the header row Athena puts first.
///
/// `GetQueryResults` repeats the column names as the first row of the **first** page of a `SELECT`.
/// Taken literally it becomes a row whose every value equals its own column name — which parses as a
/// number nowhere and is the single most likely way to get a plausible-looking wrong answer here.
fn append_rows(
    result_set: &AwsResultSet,
    columns: &Arc<Vec<Column>>,
    first_page: bool,
    rows: &mut Vec<Row>,
) {
    let page = result_set.rows();
    let page = if first_page {
        page.get(1..).unwrap_or_default()
    } else {
        page
    };

    rows.extend(page.iter().map(|row| {
        // One cell per column, whatever the page said: a row shorter than the metadata reads as
        // trailing NULLs, a longer one loses its surplus. Both are anomalies on Athena's side, and
        // neither is worth failing a whole dashboard over.
        let mut values: Vec<Option<String>> = row
            .data()
            .iter()
            .map(|datum| datum.var_char_value().map(str::to_owned))
            .collect();
        values.resize(columns.len(), None);

        Row {
            columns: columns.clone(),
            values,
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    /// `mock_instant`'s clock is process-global while the test harness runs tests on several
    /// threads at once, so one test advancing it expires another's entries mid-assertion. Every
    /// test that touches the clock takes this first.
    ///
    /// A `tokio` mutex rather than `std`'s: the guard is held across the `await`s of the cache
    /// calls, and a blocking guard held across an await is what `clippy::await_holding_lock`
    /// rejects — the lint CI runs with `--workspace`. This one also cannot be poisoned, so a
    /// panicking test leaves the next one a usable lock.
    static CLOCK: Mutex<()> = Mutex::const_new(());

    fn columns() -> Arc<Vec<Column>> {
        Arc::new(vec![
            Column {
                name: "item".to_owned(),
                type_name: "varchar".to_owned(),
            },
            Column {
                name: "calls".to_owned(),
                type_name: "bigint".to_owned(),
            },
            Column {
                name: "share".to_owned(),
                type_name: "double".to_owned(),
            },
        ])
    }

    fn row(values: &[Option<&str>]) -> Row {
        Row {
            columns: columns(),
            values: values
                .iter()
                .map(|value| value.map(str::to_owned))
                .collect(),
        }
    }

    fn result_set(rows: Vec<Row>) -> ResultSet {
        ResultSet {
            columns: columns(),
            rows,
            scanned_bytes: 0,
            execution_id: "test".to_owned(),
        }
    }

    #[test]
    fn reads_values_by_column_name() {
        let row = row(&[Some("4711"), Some("12"), Some("0.5")]);

        assert_eq!(row.get_str("item").unwrap(), "4711");
        assert_eq!(row.get_i64("calls").unwrap(), 12);
        assert_eq!(row.get_f64("share").unwrap(), 0.5);
    }

    #[test]
    fn names_the_columns_it_has_when_one_is_missing() {
        let row = row(&[Some("4711"), Some("12"), Some("0.5")]);

        let err = row.get_str("nope").unwrap_err().to_string();
        assert!(err.contains("item, calls, share"), "{err}");
    }

    #[test]
    fn distinguishes_null_from_missing() {
        let row = row(&[Some("4711"), None, None]);

        assert_eq!(row.get_opt_str("calls").unwrap(), None);
        assert!(row.get_i64("calls").is_err());
    }

    /// Everything arrives as text; without coercion a `bigint` deserializes into nothing useful.
    #[test]
    fn coerces_by_the_declared_type() {
        let json = row(&[Some("4711"), Some("12"), Some("0.5")]).to_json();

        assert_eq!(json["item"], Value::from("4711"));
        assert_eq!(json["calls"], Value::from(12));
        assert_eq!(json["share"], Value::from(0.5));
    }

    #[test]
    fn keeps_a_value_that_does_not_parse_as_its_type() {
        let json = row(&[Some("4711"), Some("not a number"), None]).to_json();

        assert_eq!(json["calls"], Value::from("not a number"));
        assert_eq!(json["share"], Value::Null);
    }

    #[test]
    fn deserializes_rows_into_a_struct() {
        #[derive(serde::Deserialize)]
        struct Article {
            item: String,
            calls: i64,
        }

        let rows = result_set(vec![
            row(&[Some("4711"), Some("12"), Some("0.5")]),
            row(&[Some("4712"), Some("3"), Some("0.1")]),
        ]);

        let articles: Vec<Article> = rows.rows_as().unwrap();
        assert_eq!(articles.len(), 2);
        assert_eq!(articles[0].item, "4711");
        assert_eq!(articles[1].calls, 3);
    }

    /// The parameters have to be part of the key, or the first tenant to run a query would answer
    /// for every tenant after it.
    #[test]
    fn cache_keys_separate_parameters() {
        let sql = "SELECT 1 WHERE tenant = ?";
        let a = Query::new(sql).bind("tenant-a");
        let b = Query::new(sql).bind("tenant-b");

        assert_ne!(a.cache_key("db"), b.cache_key("db"));
    }

    #[test]
    fn cache_keys_separate_databases() {
        let query = Query::new("SELECT 1");

        assert_ne!(query.cache_key("db-a"), query.cache_key("db-b"));
    }

    /// Concatenation must not let two different queries produce one key — not even when a
    /// parameter contains whatever a separator would have used. Parameters come from outside, so
    /// "no caller would send that byte" is not an argument available here.
    #[test]
    fn cache_keys_cannot_collide_by_concatenation() {
        let two_parameters = Query::new("SELECT ?, ?").bind("a").bind("b");
        let one_parameter = Query::new("SELECT ?, ?").bind("ab");
        assert_ne!(
            two_parameters.cache_key("db"),
            one_parameter.cache_key("db")
        );

        // The separator this used to join parts with, now just an ordinary byte in a value.
        let separator_inside = Query::new("SELECT ?, ?").bind("a\u{1f}b");
        assert_ne!(
            two_parameters.cache_key("db"),
            separator_inside.cache_key("db")
        );

        // And the database must not be able to eat into the SQL either.
        assert_ne!(
            Query::new("x").cache_key("db"),
            Query::new("").cache_key("dbx")
        );
    }

    /// Builds a results page the way Athena returns one, header row included.
    fn page(rows: Vec<Vec<Option<&str>>>) -> AwsResultSet {
        use aws_sdk_athena::types::{ColumnInfo, Datum, Row as AwsRow};

        let metadata = aws_sdk_athena::types::ResultSetMetadata::builder()
            .set_column_info(Some(
                columns()
                    .iter()
                    .map(|column| {
                        ColumnInfo::builder()
                            .name(&column.name)
                            .r#type(&column.type_name)
                            .build()
                            .unwrap()
                    })
                    .collect(),
            ))
            .build();

        AwsResultSet::builder()
            .result_set_metadata(metadata)
            .set_rows(Some(
                rows.into_iter()
                    .map(|row| {
                        AwsRow::builder()
                            .set_data(Some(
                                row.into_iter()
                                    .map(|value| {
                                        let datum = Datum::builder();
                                        match value {
                                            Some(value) => datum.var_char_value(value).build(),
                                            None => datum.build(),
                                        }
                                    })
                                    .collect(),
                            ))
                            .build()
                    })
                    .collect(),
            ))
            .build()
    }

    /// The one mistake here that would produce a plausible-looking wrong answer instead of an
    /// error: Athena repeats the column names as the first row of the first page.
    #[test]
    fn drops_the_header_row_of_the_first_page_only() {
        let first = page(vec![
            vec![Some("item"), Some("calls"), Some("share")],
            vec![Some("4711"), Some("12"), Some("0.5")],
        ]);
        let second = page(vec![vec![Some("4712"), Some("3"), Some("0.1")]]);

        let mut rows = Vec::new();
        append_rows(&first, &columns(), true, &mut rows);
        append_rows(&second, &columns(), false, &mut rows);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get_str("item").unwrap(), "4711");
        assert_eq!(rows[1].get_i64("calls").unwrap(), 3);
    }

    /// A `SELECT` that matched nothing still carries the header row, so the first page can be
    /// exactly one row long and must come back empty rather than underflow.
    #[test]
    fn an_empty_result_is_empty() {
        let only_header = page(vec![vec![Some("item"), Some("calls"), Some("share")]]);

        let mut rows = Vec::new();
        append_rows(&only_header, &columns(), true, &mut rows);

        assert!(rows.is_empty());
    }

    #[test]
    fn pads_a_row_that_is_shorter_than_its_metadata() {
        let short = page(vec![
            vec![Some("item"), Some("calls"), Some("share")],
            vec![Some("4711")],
        ]);

        let mut rows = Vec::new();
        append_rows(&short, &columns(), true, &mut rows);

        assert_eq!(rows[0].get_str("item").unwrap(), "4711");
        assert_eq!(rows[0].get_opt_str("share").unwrap(), None);
    }

    #[tokio::test]
    async fn cache_serves_an_entry_until_it_expires() {
        let _clock = CLOCK.lock().await;
        use mock_instant::global::MockClock;

        let cache = InProcessQueryCache::new(8);
        let value = Arc::new(result_set(vec![row(&[Some("4711"), Some("12"), None])]));

        cache.put("k", value, Duration::from_secs(60)).await;
        assert!(cache.get("k").await.is_some());

        MockClock::advance(Duration::from_secs(61));
        assert!(cache.get("k").await.is_none());
    }

    #[tokio::test]
    async fn cache_stays_within_its_capacity() {
        let _clock = CLOCK.lock().await;
        let cache = InProcessQueryCache::new(2);

        for index in 0..5 {
            cache
                .put(
                    &format!("k{index}"),
                    Arc::new(result_set(vec![])),
                    Duration::from_secs(60),
                )
                .await;
        }

        assert!(cache.entries.read().await.len() <= 2);
    }

    /// A capacity of zero would otherwise evict in a loop or divide by nothing; one entry is the
    /// smallest cache that still is one.
    #[tokio::test]
    async fn cache_capacity_is_at_least_one() {
        let _clock = CLOCK.lock().await;
        let cache = InProcessQueryCache::new(0);

        cache
            .put("k", Arc::new(result_set(vec![])), Duration::from_secs(60))
            .await;

        assert!(cache.get("k").await.is_some());
    }
}
