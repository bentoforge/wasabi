//! Error types and helpers for mapping errors to HTTP responses.
//!
//! The [`ApiError`] type carries both an HTTP status code and a message.
//! Use [`ResultExt`] to attach status codes to `anyhow::Error` chains,
//! or the [`client_bail!`] and [`status_bail!`] macros for early returns.

use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use warp::http::StatusCode;
use warp::reject::Reject;

/// An error that can be serialized to JSON and returned as an HTTP response.
///
/// The `status` field determines the HTTP status code but is not serialized.
#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// HTTP status code for the response (not serialized).
    #[serde(skip)]
    pub status: StatusCode,
    /// Human-readable error message. May be localized; do not match on it.
    pub message: String,
    /// Stable machine-readable identifier (e.g. `auth.invalid_credentials`), omitted when the
    /// error has none.
    ///
    /// Exists because `message` cannot serve both audiences: a CLI or a chat bot needs prose it
    /// can show as-is, while a service relaying the failure to *its* users needs something it can
    /// key its own wording off — and prose that gets localized is exactly what a caller must not
    /// match on. Purely additive: existing consumers see one more field and ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Reject for ApiError {}

impl ApiError {
    /// Creates a new API error with the given HTTP status and message, without a code.
    pub fn new(status: StatusCode, message: impl ToString) -> Self {
        ApiError {
            status,
            message: message.to_string(),
            code: None,
        }
    }

    /// Creates an API error carrying a stable `code` alongside the (possibly localized) message.
    pub fn with_code(status: StatusCode, code: impl ToString, message: impl ToString) -> Self {
        ApiError {
            status,
            message: message.to_string(),
            code: Some(code.to_string()),
        }
    }
}

/// Extension trait for attaching HTTP status codes to error results.
pub trait ResultExt<T> {
    /// Wraps the error with an [`ApiError`] carrying the given status code.
    fn with_status(self, status: StatusCode) -> Result<T, anyhow::Error>;

    /// Convenience method for `with_status(StatusCode::BAD_REQUEST)`.
    fn mark_client_error(self) -> Result<T, anyhow::Error>;
}

impl<T> ResultExt<T> for Result<T, anyhow::Error> {
    fn with_status(self, status: StatusCode) -> Result<T, anyhow::Error> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => {
                let message = format!("{:#}", err);
                Err(err.context(ApiError {
                    status,
                    message,
                    code: None,
                }))
            }
        }
    }

    fn mark_client_error(self) -> Result<T, anyhow::Error> {
        self.with_status(StatusCode::BAD_REQUEST)
    }
}

/// Early return with a 400 Bad Request error.
#[macro_export]
macro_rules! client_bail {
    ($err:expr $(,)?) => {
        return $crate::web::error::ResultExt::mark_client_error(Err(::anyhow::anyhow!($err)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return $crate::web::error::ResultExt::mark_client_error(Err(::anyhow::anyhow!($fmt, $($arg)*)))
    };
}

/// Early return with a custom HTTP status code.
#[macro_export]
macro_rules! status_bail {
    ($status:expr, $msg:literal $(,)?) => {
        return $crate::web::error::ResultExt::with_status(Err(::anyhow::anyhow!($msg)), $status)
    };
    ($status:expr, $fmt:literal, $($arg:tt)*) => {
        return $crate::web::error::ResultExt::with_status(Err(::anyhow::anyhow!($fmt, $($arg)*)), $status)
    };
}
