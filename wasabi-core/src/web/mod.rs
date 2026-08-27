//! HTTP layer built on the Warp framework.
//!
//! Provides filters for body parsing, authentication, error handling, and
//! common service endpoints. Use [`warp::run_webserver`] to start a server
//! with graceful shutdown support.

use bytesize::MB;

pub mod auth;
pub mod error;
pub mod favicon_service;
pub mod info_service;
pub mod locale;
/// PDF generation powered by Typst templates.
#[cfg(feature = "pdf")]
pub mod pdf;
pub mod user_info_service;
pub mod validation;
pub mod warp;

/// Default limit for JSON request bodies (10 MB).
pub const DEFAULT_MAX_JSON_BODY_SIZE: u64 = 10 * MB;
