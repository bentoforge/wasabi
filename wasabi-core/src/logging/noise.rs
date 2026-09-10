//! Suppression of warp's connection-teardown noise.
//!
//! Since warp 0.4 the server drives its own accept loop and logs every failed connection at
//! `ERROR` (`warp::server`: `server connection error: ...`). Most of those errors are not server
//! problems at all: a client, load balancer health check or port scanner that opens a connection
//! and drops it mid-request makes hyper fail the connection with `IncompleteMessage`, a reset or a
//! broken pipe. Under hyper 0.14 (warp 0.3) the same events were logged below `info` and never
//! showed up in production logs.
//!
//! [`ConnectionNoiseFilter`] drops exactly those peer-caused errors for the whole subscriber
//! stack. Everything else warp reports — parse errors, `accept error` (which signals real trouble
//! such as running out of file descriptors) and any error from other targets — is left untouched.
//! Set `LOG_CONNECTION_ERRORS=true` to keep the suppressed events, e.g. when debugging a client
//! that disconnects unexpectedly.

use std::env;
use std::fmt::Debug;
use std::sync::OnceLock;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Module path warp logs its per-connection errors under (`warp::server::run` today).
const WARP_SERVER_TARGET: &str = "warp::server";

/// Fragments of hyper's `Debug` output that identify a connection the peer tore down.
///
/// Matched against the formatted event message, which contains the `{:?}` rendering of the hyper
/// error, e.g. `server connection error: hyper::Error(IncompleteMessage)` or
/// `server connection error: hyper::Error(Io, Os { code: 104, kind: ConnectionReset, .. })`.
const PEER_DISCONNECT_MARKERS: [&str; 6] = [
    // Client vanished before its request was complete.
    "IncompleteMessage",
    // Peer reset or aborted the TCP connection.
    "ConnectionReset",
    "ConnectionAborted",
    // Peer stopped reading while the response was being written.
    "BrokenPipe",
    // Connection closed in the middle of the (TLS) stream or during shutdown.
    "UnexpectedEof",
    "NotConnected",
];

/// Layer that hides peer-caused connection errors from the entire subscriber stack.
///
/// Implemented via [`Layer::event_enabled`], so a suppressed event reaches neither the console nor
/// the OpenTelemetry layer.
pub(super) struct ConnectionNoiseFilter;

impl<S: Subscriber> Layer<S> for ConnectionNoiseFilter {
    fn event_enabled(&self, event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
        if log_connection_errors() {
            return true;
        }

        let metadata = event.metadata();
        if !is_warp_server_target(metadata.target()) || *metadata.level() != Level::ERROR {
            return true;
        }

        let mut message = MessageVisitor::default();
        event.record(&mut message);

        !is_peer_disconnect(&message.message)
    }
}

/// Whether warp's connection errors should be logged anyway, from `LOG_CONNECTION_ERRORS`
/// (default `false`).
///
/// A deployment property that doesn't change at runtime, so it's parsed once on first access and
/// cached — `event_enabled` runs on every event.
fn log_connection_errors() -> bool {
    static LOG_CONNECTION_ERRORS: OnceLock<bool> = OnceLock::new();
    *LOG_CONNECTION_ERRORS.get_or_init(|| {
        env::var("LOG_CONNECTION_ERRORS")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

/// Whether `target` is warp's server target or one of its submodules.
fn is_warp_server_target(target: &str) -> bool {
    target == WARP_SERVER_TARGET
        || target
            .strip_prefix(WARP_SERVER_TARGET)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// Whether `message` describes a connection the peer tore down rather than a server-side fault.
fn is_peer_disconnect(message: &str) -> bool {
    PEER_DISCONNECT_MARKERS
        .iter()
        .any(|marker| message.contains(marker))
}

/// Captures the `message` field of an event as a string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" && self.message.is_empty() {
            self.message = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry::LookupSpan;

    #[test]
    fn warps_server_target_is_recognized() {
        assert!(is_warp_server_target("warp::server"));
        assert!(is_warp_server_target("warp::server::run"));
        assert!(!is_warp_server_target("warp::servers"));
        assert!(!is_warp_server_target("warp::filters::body"));
    }

    #[test]
    fn peer_disconnects_are_recognized() {
        for message in [
            "server connection error: hyper::Error(IncompleteMessage)",
            "server connection error: hyper::Error(Io, Os { code: 104, kind: ConnectionReset, message: \"Connection reset by peer\" })",
            "server connection error: hyper::Error(BodyWrite, Os { code: 32, kind: BrokenPipe, message: \"Broken pipe\" })",
            "server connection error: hyper::Error(Io, Kind(UnexpectedEof))",
        ] {
            assert!(is_peer_disconnect(message), "should be noise: {message}");
        }
    }

    #[test]
    fn server_side_errors_are_kept() {
        for message in [
            "accept error: Os { code: 24, kind: Uncategorized, message: \"Too many open files\" }",
            "server connection error: hyper::Error(Parse(Version))",
            "server connection error: hyper::Error(User(Service))",
        ] {
            assert!(!is_peer_disconnect(message), "should be kept: {message}");
        }
    }

    /// Collects the messages of all events that make it through the filter.
    struct CollectingLayer(Arc<Mutex<Vec<String>>>);

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for CollectingLayer {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut message = MessageVisitor::default();
            event.record(&mut message);
            self.0.lock().expect("poisoned").push(message.message);
        }
    }

    #[test]
    fn the_filter_only_drops_peer_disconnects() {
        let collected = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(ConnectionNoiseFilter)
            .with(CollectingLayer(Arc::clone(&collected)));

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "warp::server::run", "server connection error: hyper::Error(IncompleteMessage)");
            tracing::error!(target: "warp::server::run", "accept error: Os {{ code: 24, kind: Uncategorized }}");
            tracing::error!(target: "my_app::handler", "server connection error: hyper::Error(IncompleteMessage)");
        });

        let collected = collected.lock().expect("poisoned");
        assert_eq!(
            *collected,
            vec![
                "accept error: Os { code: 24, kind: Uncategorized }".to_string(),
                "server connection error: hyper::Error(IncompleteMessage)".to_string(),
            ]
        );
    }
}
