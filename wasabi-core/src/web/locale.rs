//! Picking a language for a response.
//!
//! Two sources, in this order:
//!
//! 1. The caller's `locale` claim ([`crate::web::auth::user::User::locale`]) — a stated
//!    preference, and the one that should win. `Accept-Language` describes the *device*: someone
//!    who chose German in their profile should not be answered in Spanish because they opened a
//!    borrowed laptop abroad.
//! 2. `Accept-Language`, for callers with no token yet — a sign-in page has no preference to
//!    honour, so the browser's hint is the only signal there is.
//!
//! Whatever is left over falls back to the deployment's default. [`negotiate_language`] does the
//! second step; the first is a plain read off the token.

use warp::Filter;
use warp::Rejection;

/// The `Accept-Language` header, if the client sent one.
pub fn accept_language() -> impl Filter<Extract = (Option<String>,), Error = Rejection> + Clone {
    warp::header::optional::<String>("accept-language")
}

/// Picks the best of `supported` for an `Accept-Language` header, else `default`.
///
/// Follows RFC 9110 far enough to be useful and no further: entries are ranked by their `q` value
/// (absent means 1.0, `q=0` means "not this one"), and each is matched first exactly, then by its
/// primary subtag — so `de-AT` reaches a catalogue that only has `de`. A wildcard `*` selects
/// `default`. Comparison is case-insensitive, because these tags arrive as typed.
///
/// `supported` is expected to be small and is scanned linearly; it is a list of translations, not
/// a data structure.
pub fn negotiate_language(header: Option<&str>, supported: &[&str], default: &str) -> String {
    let Some(header) = header else {
        return default.to_owned();
    };

    let mut ranked: Vec<(f32, &str)> = header
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.split(';');
            let tag = parts.next()?.trim();
            if tag.is_empty() {
                return None;
            }
            // Only `q=` is meaningful to us; any other parameter is ignored rather than rejected,
            // since a header we cannot fully parse is still worth honouring in part.
            let quality = parts
                .find_map(|param| {
                    let (key, value) = param.split_once('=')?;
                    key.trim().eq_ignore_ascii_case("q").then(|| value.trim())
                })
                .and_then(|value| value.parse::<f32>().ok())
                .unwrap_or(1.0);
            (quality > 0.0).then_some((quality, tag))
        })
        .collect();

    // Descending by quality, stable so equal weights keep the client's own order — which is the
    // order the client meant them in.
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));

    for (_, tag) in ranked {
        if tag == "*" {
            return default.to_owned();
        }
        if let Some(hit) = supported.iter().find(|s| s.eq_ignore_ascii_case(tag)) {
            return (*hit).to_owned();
        }
        let primary = tag.split(['-', '_']).next().unwrap_or_default();
        if let Some(hit) = supported.iter().find(|s| s.eq_ignore_ascii_case(primary)) {
            return (*hit).to_owned();
        }
    }
    default.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED: &[&str] = &["de", "en"];

    #[test]
    fn no_header_yields_the_default() {
        assert_eq!(negotiate_language(None, SUPPORTED, "en"), "en");
        assert_eq!(negotiate_language(Some(""), SUPPORTED, "de"), "de");
    }

    #[test]
    fn quality_decides_over_position() {
        // English comes first in the header but is explicitly weighted lower.
        assert_eq!(
            negotiate_language(Some("en;q=0.5,de;q=0.9"), SUPPORTED, "en"),
            "de"
        );
    }

    #[test]
    fn equal_quality_keeps_the_clients_order() {
        assert_eq!(negotiate_language(Some("de,en"), SUPPORTED, "en"), "de");
        assert_eq!(negotiate_language(Some("en,de"), SUPPORTED, "de"), "en");
    }

    #[test]
    fn region_subtags_reach_the_language() {
        assert_eq!(negotiate_language(Some("de-AT"), SUPPORTED, "en"), "de");
        assert_eq!(negotiate_language(Some("DE-ch"), SUPPORTED, "en"), "de");
    }

    #[test]
    fn q_zero_is_a_refusal_not_a_preference() {
        // `de;q=0` says "anything but German" — it must not be picked despite being listed.
        assert_eq!(
            negotiate_language(Some("de;q=0,en;q=0.1"), SUPPORTED, "de"),
            "en"
        );
    }

    #[test]
    fn unsupported_languages_fall_through_to_the_default() {
        assert_eq!(negotiate_language(Some("fr,it"), SUPPORTED, "en"), "en");
    }

    #[test]
    fn wildcard_selects_the_default() {
        assert_eq!(negotiate_language(Some("fr,*"), SUPPORTED, "de"), "de");
    }

    #[test]
    fn a_malformed_entry_does_not_discard_the_rest() {
        assert_eq!(
            negotiate_language(Some("xx;;,de;q=bogus"), SUPPORTED, "en"),
            "de",
            "an unparsable q falls back to 1.0 rather than dropping the entry"
        );
    }
}
