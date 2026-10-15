use std::fmt::Display;
use tokio_postgres::error::SqlState;

/// The outcome of a failed database operation, classified by what a caller can do about it.
///
/// Most callers do nothing and let it travel: `?` turns it into an `anyhow::Error` like any other
/// error, and the variant stays recoverable from the chain via [`Error::find`]. The variants exist
/// for the few places that do react — retrying an insert under a freshly generated key, mapping a
/// duplicate to a `409`, re-running a transaction that lost a serialization race.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A primary key or unique index already holds this value.
    #[error("{context}: duplicate key")]
    UniqueViolation {
        /// What was being done.
        context: String,
        /// The violated constraint or index, when Postgres names it.
        constraint: Option<String>,
        /// The driver's error.
        #[source]
        source: tokio_postgres::Error,
    },

    /// A foreign key points nowhere, or a row is still referenced.
    #[error("{context}: foreign key violated")]
    ForeignKeyViolation {
        /// What was being done.
        context: String,
        /// The violated constraint, when Postgres names it.
        constraint: Option<String>,
        /// The driver's error.
        #[source]
        source: tokio_postgres::Error,
    },

    /// The transaction lost a race (serialization failure or deadlock) and succeeds when run
    /// again from the start.
    #[error("{context}: lost to a concurrent transaction, retry it")]
    Retryable {
        /// What was being done.
        context: String,
        /// The driver's error.
        #[source]
        source: tokio_postgres::Error,
    },

    /// Anything else: an unreachable database, a rejected statement, an invalid record. Nothing a
    /// caller can fix at runtime — pass it on.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// `Result` with [`Error`] as the default error.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Classifies a driver error, with `context` saying what was being done.
    pub fn from_driver(source: tokio_postgres::Error, context: impl Display) -> Self {
        let context = context.to_string();
        let code = source.code().cloned();
        let constraint = source
            .as_db_error()
            .and_then(|db| db.constraint())
            .map(str::to_owned);

        match code {
            Some(code) if code == SqlState::UNIQUE_VIOLATION => Error::UniqueViolation {
                context,
                constraint,
                source,
            },
            Some(code) if code == SqlState::FOREIGN_KEY_VIOLATION => Error::ForeignKeyViolation {
                context,
                constraint,
                source,
            },
            Some(code)
                if code == SqlState::T_R_SERIALIZATION_FAILURE
                    || code == SqlState::T_R_DEADLOCK_DETECTED =>
            {
                Error::Retryable { context, source }
            }
            _ => Error::Other(anyhow::Error::new(source).context(context)),
        }
    }

    /// An [`Error::Other`] carrying `message`.
    pub fn other(message: impl Display) -> Self {
        Error::Other(anyhow::anyhow!("{message}"))
    }

    /// Whether this is an [`Error::UniqueViolation`].
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, Error::UniqueViolation { .. })
    }

    /// Whether running the same transaction again may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Retryable { .. })
    }

    /// The violated constraint or index, for the violation variants.
    pub fn constraint(&self) -> Option<&str> {
        match self {
            Error::UniqueViolation { constraint, .. }
            | Error::ForeignKeyViolation { constraint, .. } => constraint.as_deref(),
            _ => None,
        }
    }

    /// The classified error inside an `anyhow` chain — for code that only sees the error after a
    /// `?` or `.context()` turned it into an `anyhow::Error`.
    pub fn find(err: &anyhow::Error) -> Option<&Error> {
        err.chain().find_map(|cause| cause.downcast_ref::<Error>())
    }
}

/// So a plain `client.execute(…)?` inside a function returning [`Result`] is classified too.
impl From<tokio_postgres::Error> for Error {
    fn from(source: tokio_postgres::Error) -> Self {
        Error::from_driver(source, "PostgreSQL statement failed")
    }
}

/// How many times [`retry`] runs an operation again after its first attempt.
const RETRIES: usize = 2;

/// Runs `operation`, and runs it again — at most twice — while it fails with
/// [`Error::UniqueViolation`] or [`Error::Retryable`]. Any other error, and the third failure,
/// is returned as is.
///
/// Made for the two everyday races: an insert under a freshly generated key that happens to
/// collide, and a transaction that lost a serialization conflict. A retry only helps when the
/// next attempt differs, so `operation` must do the *whole* thing again — generate the key,
/// start the transaction — rather than resend a value it captured. Wrapping an insert under a
/// caller-chosen key (a username) is pointless: it fails three times instead of once.
///
/// `operation` is a closure returning a future rather than an async closure: the future of an
/// `AsyncFnMut` cannot be proven `Send` yet, which would rule `retry` out of every
/// `#[async_trait]` method and request handler. Borrow what the closure needs beforehand and
/// `move` the references in:
///
/// ```rust,ignore
/// let client = &db.client().await?;
/// let id = postgres::retry(|| async move {
///     let id = generate_id();
///     table.insert(client, record! { "id" => id.as_str(), "event" => "login" }).await?;
///     Ok(id)
/// })
/// .await?;
/// ```
pub async fn retry<T, F, Fut>(mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut retries = 0;
    loop {
        match operation().await {
            Err(err) if retries < RETRIES && (err.is_unique_violation() || err.is_retryable()) => {
                retries += 1;
                tracing::debug!(
                    "Retrying after a recoverable database error ({retries}/{RETRIES}): {err:#}"
                );
            }
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::test::database;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Makes the server fail with `code`, so each class is produced deterministically instead of
    /// by staging a real race.
    async fn fail_with(db: &crate::postgres::Database, code: &str) -> Result<()> {
        let client = db.client().await?;
        client
            .batch_execute(&format!(
                "DO $$ BEGIN RAISE EXCEPTION 'provoked' USING ERRCODE = '{code}'; END $$"
            ))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn driver_errors_are_classified() {
        let Some(db) = database().await else { return };
        assert!(
            fail_with(&db, "23505")
                .await
                .unwrap_err()
                .is_unique_violation()
        );
        assert!(matches!(
            fail_with(&db, "23503").await.unwrap_err(),
            Error::ForeignKeyViolation { .. }
        ));
        assert!(fail_with(&db, "40001").await.unwrap_err().is_retryable());
        assert!(fail_with(&db, "40P01").await.unwrap_err().is_retryable());
        assert!(matches!(
            fail_with(&db, "22012").await.unwrap_err(),
            Error::Other(_)
        ));
    }

    #[tokio::test]
    async fn retry_is_send_so_async_trait_methods_can_use_it() {
        fn assert_send<T: Send>(_: &T) {}
        let Some(db) = database().await else { return };
        let db = &db;
        let operation = retry(|| async move { fail_with(db, "23505").await });
        assert_send(&operation);
        assert!(operation.await.unwrap_err().is_unique_violation());
    }

    #[tokio::test]
    async fn retry_runs_again_after_a_recoverable_error() {
        let Some(db) = database().await else { return };
        let attempts = &AtomicUsize::new(0);
        let db = &db;
        let outcome = retry(|| async move {
            if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                fail_with(&db, "23505").await?;
            }
            Ok("stored")
        })
        .await;
        assert_eq!(outcome.unwrap(), "stored");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_gives_up_after_two_retries() {
        let Some(db) = database().await else { return };
        let attempts = &AtomicUsize::new(0);
        let db = &db;
        let outcome: Result<()> = retry(|| async move {
            let _ = attempts.fetch_add(1, Ordering::SeqCst);
            fail_with(&db, "40001").await
        })
        .await;
        assert!(outcome.unwrap_err().is_retryable());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_passes_other_errors_straight_through() {
        let Some(db) = database().await else { return };
        let attempts = &AtomicUsize::new(0);
        let db = &db;
        let outcome: Result<()> = retry(|| async move {
            let _ = attempts.fetch_add(1, Ordering::SeqCst);
            fail_with(&db, "22012").await
        })
        .await;
        assert!(matches!(outcome.unwrap_err(), Error::Other(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
