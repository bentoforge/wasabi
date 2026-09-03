//! JWT validation with support for multiple issuers and key strategies.
//!
//! The [`Authenticator`] validates JWT tokens using either a shared secret (HMAC)
//! or JWKS endpoints, with per-issuer configuration. Custom claim prefixes can be
//! stripped to normalize claims from different identity providers.

use crate::status_bail;
use crate::web::auth::claim_transformer::ClaimTransformer;
use crate::web::auth::jwks::{JwksCache, UrlJwksFetcher};
use crate::web::auth::user::ClaimsSet;
use crate::web::auth::{CLAIM_ISS, CLAIM_LOCALE, DEFAULT_LOCALE};
use crate::web::error::ResultExt;
use crate::web::locale::negotiate_language;
use anyhow::{Context, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use warp::http::StatusCode;

/// Trait for dynamically fetching authenticator config based on JWT claims.
///
/// Implement this to support multi-tenant scenarios where different tenants
/// use different identity providers.
#[async_trait]
pub trait ConfigFetcher: Send + Sync {
    /// Returns authenticator config for the given claims, or `None` if not applicable.
    async fn fetch(&self, claims: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>>;
}

/// Validates JWTs and extracts claims.
pub struct Authenticator {
    config: AuthenticatorConfig,
    fetchers: Vec<Box<dyn ConfigFetcher>>,
}

impl Authenticator {
    /// Creates an authenticator with the given configuration.
    pub fn new(config: AuthenticatorConfig) -> Self {
        Authenticator {
            config,
            fetchers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn with_simple_secret(secret: &str) -> Self {
        let key = Arc::new(DecodingKey::from_secret(secret.as_bytes()));
        Self::new(AuthenticatorConfig::new(
            None,
            HashSet::new(),
            None,
            DEFAULT_LOCALE.to_string(),
            None,
            Arc::new(HmacKeyFetcher::new(key)),
            None,
        ))
    }

    /// Creates an authenticator from environment variables.
    ///
    /// # Environment Variables
    /// - `AUTH_SECRET` - Shared secret for HMAC validation
    /// - `AUTH_ALGORITHMS` - Comma-separated list of allowed algorithms
    /// - `AUTH_ISSUER` - Comma-separated issuers, optionally with config (e.g., `iss1,iss2=jwks:/url`)
    /// - `AUTH_AUDIENCE` - Expected audience claim
    /// - `DEFAULT_LOCALE` - Fallback locale if not in token
    /// - `AUTH_CUSTOM_CLAIM_PREFIX` - Prefix to strip from custom claims
    pub fn from_env() -> anyhow::Result<Self> {
        let config = AuthenticatorConfig::from_env_style_config(
            env::var("AUTH_SECRET").ok(),
            &env::var("AUTH_ALGORITHMS").ok().unwrap_or_default(),
            &env::var("AUTH_ISSUER").ok().unwrap_or_default(),
            &env::var("AUTH_AUDIENCE").ok().unwrap_or_default(),
            env::var("DEFAULT_LOCALE")
                .ok()
                .unwrap_or_else(|| DEFAULT_LOCALE.to_string()),
            env::var("AUTH_CUSTOM_CLAIM_PREFIX").ok(),
        )?;

        Ok(Self::new(config))
    }

    /// Adds a dynamic config fetcher for multi-tenant scenarios.
    pub fn add_fetcher(&mut self, fetcher: Box<dyn ConfigFetcher>) {
        self.fetchers.push(fetcher);
    }

    /// Sets the languages this deployment can produce, so a token carrying no `locale` claim is
    /// answered from the request's `Accept-Language` rather than the bare default. Convenience over
    /// [`AuthenticatorConfig::with_supported_locales`] for the common `Authenticator::from_env()?`
    /// construction path.
    #[must_use]
    pub fn with_supported_locales(mut self, locales: Vec<String>) -> Self {
        self.config = self.config.with_supported_locales(locales);
        self
    }

    /// Validates the JWT and returns the extracted claims.
    #[tracing::instrument(level = "debug", skip(self, jwt_token), err(Display))]
    pub async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<ClaimsSet> {
        self.parse_jwt_localized(jwt_token, None).await
    }

    /// Like [`Self::parse_jwt`], but with the request's `Accept-Language` in hand.
    ///
    /// It matters only when the token carries no `locale` claim: instead of blindly injecting the
    /// deployment default, the header is negotiated against the configured supported languages (see
    /// [`AuthenticatorConfig::with_supported_locales`]), so a caller whose token never carried a
    /// language is still answered in one they actually asked for. With no supported set configured,
    /// or no header, this is identical to [`Self::parse_jwt`].
    pub async fn parse_jwt_localized(
        &self,
        jwt_token: &str,
        accept_language: Option<&str>,
    ) -> anyhow::Result<ClaimsSet> {
        let claims = Self::decode_payload(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        if let Some(config) = self.try_fetch_config(&claims).await {
            Self::parse_validate_and_update(jwt_token, &claims, &config, accept_language).await
        } else {
            Self::parse_validate_and_update(jwt_token, &claims, &self.config, accept_language).await
        }
    }

    fn decode_payload(jwt_token: &str) -> anyhow::Result<ClaimsSet> {
        if let Some(payload) = jwt_token.split('.').nth(1) {
            let decoded = URL_SAFE_NO_PAD
                .decode(payload)
                .context("Cannot decode Base64 payload")
                .with_status(StatusCode::UNAUTHORIZED)?;
            serde_json::from_slice(&decoded)
                .context("Cannot parse payload as JSON")
                .with_status(StatusCode::UNAUTHORIZED)
        } else {
            bail!("Cannot extract payload part")
        }
    }

    async fn parse_validate_and_update(
        jwt_token: &str,
        claims: &ClaimsSet,
        config: &AuthenticatorConfig,
        accept_language: Option<&str>,
    ) -> anyhow::Result<ClaimsSet> {
        let mut claims = config.check_signature(claims, jwt_token).await?;

        if let Some(custom_claim_prefix) = &config.custom_claim_prefix {
            claims = Self::translate_claims(claims, custom_claim_prefix);
        }

        if let Some(transformer) = &config.claim_transformer {
            transformer.apply(&mut claims);
        }

        Self::inject_locale_if_missing(&mut claims, config, accept_language);

        Ok(claims)
    }

    async fn try_fetch_config(&self, claims_set: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>> {
        for fetcher in &self.fetchers {
            if let Some(config) = fetcher.fetch(claims_set).await {
                return Some(config);
            }
        }

        None
    }

    fn translate_claims(claims: ClaimsSet, custom_claim_prefix: &str) -> ClaimsSet {
        claims
            .into_iter()
            .map(|(key, value)| {
                if key.starts_with(custom_claim_prefix) {
                    let new_key = key.trim_start_matches(custom_claim_prefix).to_string();
                    (new_key, value)
                } else {
                    (key, value)
                }
            })
            .collect()
    }

    /// Ensures a `locale` claim is present, choosing the best one available.
    ///
    /// A token that already names a locale keeps it. Otherwise the request's `Accept-Language` is
    /// negotiated against the configured supported languages — so the caller is answered in a
    /// language they asked for *and* the deployment can actually produce — and only if that finds
    /// nothing (or no supported set was configured) does the deployment default apply. Injecting it
    /// here, once, is what lets every downstream `User::locale()` stay a single claim read.
    fn inject_locale_if_missing(
        claims: &mut ClaimsSet,
        config: &AuthenticatorConfig,
        accept_language: Option<&str>,
    ) {
        if claims.get(CLAIM_LOCALE).is_some() {
            return;
        }
        let chosen = if config.supported_locales.is_empty() {
            config.default_locale.clone()
        } else {
            let supported: Vec<&str> = config
                .supported_locales
                .iter()
                .map(String::as_str)
                .collect();
            negotiate_language(accept_language, &supported, &config.default_locale)
        };
        let _ = claims.insert(CLAIM_LOCALE.to_string(), Value::String(chosen));
    }
}

/// Configuration for JWT validation.
pub struct AuthenticatorConfig {
    validation: Validation,
    default_locale: String,
    /// Languages the deployment can actually produce, for negotiating a token that carries no
    /// `locale` claim against the request's `Accept-Language`. Empty = no negotiation (the default
    /// locale is injected as before). Set via [`Self::with_supported_locales`].
    supported_locales: Vec<String>,
    custom_claim_prefix: Option<String>,
    key_fetcher: KeyFetchStrategy,
    claim_transformer: Option<ClaimTransformer>,
}

/// Strategy for fetching decoding keys - either a single key for all issuers
/// or a different key source per issuer.
enum KeyFetchStrategy {
    Static(Arc<dyn KeyFetcher>),
    PerIssuer(HashMap<String, Arc<dyn KeyFetcher>>),
}

/// Trait for fetching JWT decoding keys.
///
/// Implement this trait to support custom key sources (e.g., custom JWKS endpoints,
/// key vaults, or other key management systems).
#[async_trait]
pub trait KeyFetcher: Send + Sync {
    /// Fetches the decoding key for the given JWT header.
    async fn fetch(&self, header: &Header) -> anyhow::Result<Arc<DecodingKey>>;
}

/// Key fetcher for HMAC-based (shared secret) JWT validation.
///
/// Use this when validating JWTs signed with a symmetric secret key (HS256, HS384, HS512).
///
/// # Example
///
/// ```
/// use wasabi_core::web::auth::authenticator::HmacKeyFetcher;
/// use jsonwebtoken::DecodingKey;
/// use std::sync::Arc;
///
/// let key = Arc::new(DecodingKey::from_secret(b"my-secret-key"));
/// let fetcher = HmacKeyFetcher::new(key);
/// ```
pub struct HmacKeyFetcher {
    hmac_key: Arc<DecodingKey>,
}

impl HmacKeyFetcher {
    /// Creates a new HMAC key fetcher with the given decoding key.
    pub fn new(hmac_key: Arc<DecodingKey>) -> Self {
        Self { hmac_key }
    }
}

#[async_trait]
impl KeyFetcher for HmacKeyFetcher {
    async fn fetch(&self, _header: &Header) -> anyhow::Result<Arc<DecodingKey>> {
        Ok(self.hmac_key.clone())
    }
}

/// Key fetcher for JWKS (JSON Web Key Set) based JWT validation.
///
/// Fetches public keys from a JWKS endpoint for validating JWTs signed with
/// asymmetric algorithms (RS256, ES256, etc.). Keys are cached and refreshed
/// automatically.
///
/// # Example
///
/// ```
/// use wasabi_core::web::auth::authenticator::JwksFetcher;
///
/// let fetcher = JwksFetcher::new("https://example.com/.well-known/jwks.json".to_string());
/// ```
pub struct JwksFetcher {
    jwks_cache: JwksCache,
}

impl JwksFetcher {
    /// Creates a new JWKS fetcher for the given URL.
    pub fn new(jwks_url: String) -> Self {
        Self {
            jwks_cache: JwksCache::new(Box::new(UrlJwksFetcher::new(jwks_url))),
        }
    }
}

#[async_trait]
impl KeyFetcher for JwksFetcher {
    async fn fetch(&self, header: &Header) -> anyhow::Result<Arc<DecodingKey>> {
        if let Some(kid) = &header.kid {
            self.jwks_cache.fetch_key(kid).await
        } else {
            Err(anyhow::anyhow!("No kid present in JWT header"))
        }
    }
}

impl AuthenticatorConfig {
    /// Creates a new authenticator configuration.
    ///
    /// # Arguments
    ///
    /// * `algorithms` - Allowed JWT algorithms (e.g., `Some("RS256,ES256")`). `None` allows any algorithm.
    /// * `issuers` - Set of allowed token issuers.
    /// * `audience` - Expected audience claim. `None` skips audience validation.
    /// * `default_locale` - Fallback locale if not present in token.
    /// * `custom_claim_prefix` - Prefix to strip from custom claims (e.g., `"custom:"`).
    /// * `key_fetcher` - Strategy for fetching decoding keys.
    /// * `claim_transformer` - Optional transformation rules for claims.
    ///
    /// # Example
    ///
    /// ```
    /// use wasabi_core::web::auth::authenticator::{AuthenticatorConfig, JwksFetcher};
    /// use std::sync::Arc;
    ///
    /// let config = AuthenticatorConfig::new(
    ///     Some("RS256"),
    ///     ["https://token.actions.githubusercontent.com".to_string()].into(),
    ///     None,
    ///     "en-US".to_string(),
    ///     None,
    ///     Arc::new(JwksFetcher::new("https://token.actions.githubusercontent.com/.well-known/jwks".to_string())),
    ///     None,
    /// );
    /// ```
    pub fn new(
        algorithms: Option<&str>,
        issuers: HashSet<String>,
        audience: Option<&str>,
        default_locale: String,
        custom_claim_prefix: Option<String>,
        key_fetcher: Arc<dyn KeyFetcher>,
        claim_transformer: Option<ClaimTransformer>,
    ) -> Self {
        let validation = Self::build_validation(algorithms, &issuers, audience);

        AuthenticatorConfig {
            validation,
            default_locale,
            supported_locales: Vec::new(),
            custom_claim_prefix,
            key_fetcher: KeyFetchStrategy::Static(key_fetcher),
            claim_transformer,
        }
    }

    /// Sets the languages this deployment can produce, enabling `Accept-Language` negotiation for
    /// tokens that carry no `locale` claim (see [`Authenticator::parse_jwt_localized`]). Order is
    /// irrelevant; matching is by tag with primary-subtag fallback. Empty leaves negotiation off.
    #[must_use]
    pub fn with_supported_locales(mut self, locales: Vec<String>) -> Self {
        self.supported_locales = locales;
        self
    }

    /// Creates an authenticator configuration from environment-style string parameters.
    ///
    /// This is a convenience constructor that parses comma-separated issuers with optional
    /// per-issuer configuration (e.g., `issuer1,issuer2=jwks:/.well-known/jwks.json`).
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - HMAC secret for issuers using symmetric signing.
    /// * `algorithms` - Comma-separated allowed algorithms (empty string allows any).
    /// * `issuer` - Comma-separated issuers, optionally with config: `iss=jwks:/path` or `iss=secret`.
    /// * `audience` - Expected audience (empty string skips validation).
    /// * `default_locale` - Fallback locale.
    /// * `custom_claim_prefix` - Prefix to strip from custom claims.
    pub fn from_env_style_config(
        shared_secret: Option<impl AsRef<str>>,
        algorithms: &str,
        issuer: &str,
        audience: &str,
        default_locale: String,
        custom_claim_prefix: Option<String>,
    ) -> anyhow::Result<Self> {
        let hmac_based_key =
            shared_secret.map(|str| Arc::new(DecodingKey::from_secret(str.as_ref().as_bytes())));
        let issuers: HashMap<String, String> = issuer
            .split(',')
            .map(|iss| iss.split_once('=').unwrap_or((iss, "")))
            .map(|(iss, config)| (iss.to_owned(), config.to_owned()))
            .collect();
        let issuer_names: HashSet<String> = issuers.keys().cloned().collect();
        let validation = Self::build_validation(
            Self::non_empty(algorithms),
            &issuer_names,
            Self::non_empty(audience),
        );
        let key_fetcher = Self::build_key_fetcher_strategy(issuers, hmac_based_key)?;

        Ok(AuthenticatorConfig {
            validation,
            default_locale,
            supported_locales: Vec::new(),
            custom_claim_prefix,
            key_fetcher,
            claim_transformer: None,
        })
    }

    fn non_empty(s: &str) -> Option<&str> {
        if s.is_empty() { None } else { Some(s) }
    }

    fn build_validation(
        algorithms: Option<&str>,
        issuers: &HashSet<String>,
        audience: Option<&str>,
    ) -> Validation {
        let mut validation = Validation::default();

        validation.validate_nbf = true;
        validation.algorithms = algorithms.map(Self::parse_algorithms).unwrap_or_default();
        validation.iss = Some(issuers.iter().cloned().collect());
        validation.aud = audience.and_then(Self::parse_set);

        // If we chose to leave the required audiences empty, we skip validation entirely as
        // otherwise, the JWT library will always report an error even if no audience is given and
        // none is requested.
        validation.validate_aud = validation
            .aud
            .as_ref()
            .map(|aud| !aud.is_empty())
            .unwrap_or(false);

        validation
    }

    fn parse_set(values: &str) -> Option<HashSet<String>> {
        Some(
            values
                .split(',')
                .flat_map(|part| part.split(';'))
                .map(str::trim)
                .map(String::from)
                .filter(|s| !s.is_empty())
                .collect::<HashSet<String>>(),
        )
        .filter(|set| !set.is_empty())
    }

    fn build_key_fetcher_strategy(
        issuers: HashMap<String, String>,
        hmac_key: Option<Arc<DecodingKey>>,
    ) -> anyhow::Result<KeyFetchStrategy> {
        if issuers.is_empty()
            || issuers
                .iter()
                .all(|(_, config)| config.is_empty() || *config == "secret")
        {
            if let Some(hmac_key) = hmac_key {
                Ok(KeyFetchStrategy::Static(Arc::new(HmacKeyFetcher::new(
                    hmac_key,
                ))))
            } else {
                Err(anyhow::anyhow!(
                    "All issuers rely on a shared secret to be present, but none was given"
                ))
            }
        } else {
            let mut config_per_issuer = HashMap::new();

            for (iss, config) in issuers {
                let fetcher = Self::create_key_fetcher_from_config(&iss, config, &hmac_key)?;
                let _ = config_per_issuer.insert(iss, fetcher);
            }

            Ok(KeyFetchStrategy::PerIssuer(config_per_issuer))
        }
    }

    fn create_key_fetcher_from_config(
        iss: &str,
        config: String,
        hmac_key: &Option<Arc<DecodingKey>>,
    ) -> anyhow::Result<Arc<dyn KeyFetcher>> {
        if config.is_empty() || config == "secret" {
            if let Some(hmac_key) = hmac_key {
                Ok(Arc::new(HmacKeyFetcher::new(hmac_key.clone())))
            } else {
                Err(anyhow::anyhow!(
                    "Issuer {} relies on a shared secret, but none was given",
                    iss
                ))
            }
        } else if let Some(jwks_url) = config.strip_prefix("jwks:") {
            let jwks_url = if jwks_url.starts_with('/') {
                format!("{}{}", iss.trim_matches('/'), jwks_url)
            } else {
                jwks_url.to_owned()
            };

            Ok(Arc::new(JwksFetcher::new(jwks_url)))
        } else {
            Err(anyhow::anyhow!(
                "Issuer {} has an invalid config: {}",
                iss,
                config
            ))
        }
    }

    fn parse_algorithms(algorithms: &str) -> Vec<Algorithm> {
        Self::parse_set(algorithms)
            .map(|set| {
                set.iter()
                    .filter_map(|alg| Algorithm::from_str(alg).ok())
                    .collect::<Vec<Algorithm>>()
            })
            .unwrap_or_default()
    }

    async fn check_signature(
        &self,
        claims: &ClaimsSet,
        jwt_token: &str,
    ) -> anyhow::Result<ClaimsSet> {
        let header = decode_header(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        if !self.validation.algorithms.is_empty()
            && !self.validation.algorithms.contains(&header.alg)
        {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "Invalid JWT present: Unsupported algorithm: {:?}",
                header.alg
            );
        }

        let key_fetcher = match &self.key_fetcher {
            KeyFetchStrategy::Static(fetcher) => fetcher.clone(),
            KeyFetchStrategy::PerIssuer(fetcher_per_issuer) => {
                if let Some(fetcher) = claims
                    .get(CLAIM_ISS)
                    .and_then(Value::as_str)
                    .and_then(|iss| fetcher_per_issuer.get(iss))
                {
                    fetcher.clone()
                } else {
                    status_bail!(
                        StatusCode::UNAUTHORIZED,
                        "Invalid issuer or missing configuration"
                    )
                }
            }
        };

        let decoding_key = key_fetcher
            .fetch(&header)
            .await
            .with_status(StatusCode::UNAUTHORIZED)?;
        self.validate_signature(&header, &decoding_key, jwt_token)
    }

    fn validate_signature(
        &self,
        header: &Header,
        decoding_key: &DecodingKey,
        jwt_token: &str,
    ) -> anyhow::Result<ClaimsSet> {
        let mut validation = self.validation.clone();
        validation.algorithms = vec![header.alg];

        let token = decode::<ClaimsSet>(jwt_token, decoding_key, &validation)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        Ok(token.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // translate_claims tests

    #[test]
    fn translate_claims_strips_prefix() {
        let mut claims = ClaimsSet::new();
        claims.insert("custom:tenant".to_string(), json!("abc"));
        claims.insert("custom:role".to_string(), json!("admin"));
        claims.insert("sub".to_string(), json!("user123"));

        let translated = Authenticator::translate_claims(claims, "custom:");

        assert_eq!(translated.get("tenant").unwrap(), &json!("abc"));
        assert_eq!(translated.get("role").unwrap(), &json!("admin"));
        assert_eq!(translated.get("sub").unwrap(), &json!("user123"));
        assert!(!translated.contains_key("custom:tenant"));
    }

    #[test]
    fn translate_claims_leaves_non_matching_unchanged() {
        let mut claims = ClaimsSet::new();
        claims.insert("other:claim".to_string(), json!("value"));
        claims.insert("sub".to_string(), json!("user123"));

        let translated = Authenticator::translate_claims(claims, "custom:");

        assert_eq!(translated.get("other:claim").unwrap(), &json!("value"));
        assert_eq!(translated.get("sub").unwrap(), &json!("user123"));
    }

    // inject_locale_if_missing tests

    /// A config with the given default and supported languages, over a throwaway HMAC key.
    fn locale_config(default: &str, supported: &[&str]) -> AuthenticatorConfig {
        let key = Arc::new(DecodingKey::from_secret(b"secret"));
        AuthenticatorConfig::new(
            None,
            HashSet::new(),
            None,
            default.to_string(),
            None,
            Arc::new(HmacKeyFetcher::new(key)),
            None,
        )
        .with_supported_locales(supported.iter().map(|s| (*s).to_string()).collect())
    }

    #[test]
    fn inject_locale_adds_default_when_missing() {
        let mut claims = ClaimsSet::new();
        claims.insert("sub".to_string(), json!("user123"));

        Authenticator::inject_locale_if_missing(&mut claims, &locale_config("de-DE", &[]), None);

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("de-DE"));
    }

    #[test]
    fn inject_locale_preserves_existing() {
        let mut claims = ClaimsSet::new();
        claims.insert(CLAIM_LOCALE.to_string(), json!("fr-FR"));

        Authenticator::inject_locale_if_missing(&mut claims, &locale_config("de-DE", &[]), None);

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("fr-FR"));
    }

    #[test]
    fn inject_locale_negotiates_accept_language_against_supported() {
        let mut claims = ClaimsSet::new();
        // Top preference `fr` is not supported; `de` (lower q) is — negotiation must pick it, not
        // the first tag and not the default.
        Authenticator::inject_locale_if_missing(
            &mut claims,
            &locale_config("en", &["de", "en"]),
            Some("fr;q=0.9, de;q=0.8, en;q=0.7"),
        );

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("de"));
    }

    #[test]
    fn inject_locale_falls_back_to_default_when_nothing_matches() {
        let mut claims = ClaimsSet::new();
        Authenticator::inject_locale_if_missing(
            &mut claims,
            &locale_config("en", &["de", "en"]),
            Some("es-ES"),
        );

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("en"));
    }

    // decode_payload tests

    #[test]
    fn decode_payload_extracts_claims() {
        // JWT with payload: {"sub": "1234", "name": "Test"}
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IlRlc3QifQ.signature";

        let claims = Authenticator::decode_payload(jwt).unwrap();

        assert_eq!(claims.get("sub").unwrap(), &json!("1234"));
        assert_eq!(claims.get("name").unwrap(), &json!("Test"));
    }

    #[test]
    fn decode_payload_fails_on_invalid_jwt() {
        let result = Authenticator::decode_payload("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn decode_payload_fails_on_invalid_base64() {
        let result = Authenticator::decode_payload("header.!!!invalid!!!.signature");
        assert!(result.is_err());
    }

    // parse_set tests

    #[test]
    fn parse_set_splits_by_comma() {
        let result = AuthenticatorConfig::parse_set("a,b,c").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn parse_set_splits_by_semicolon() {
        let result = AuthenticatorConfig::parse_set("a;b;c").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn parse_set_handles_mixed_separators() {
        let result = AuthenticatorConfig::parse_set("a,b;c").unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn parse_set_trims_whitespace() {
        let result = AuthenticatorConfig::parse_set(" a , b , c ").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn parse_set_returns_none_for_empty() {
        assert!(AuthenticatorConfig::parse_set("").is_none());
        assert!(AuthenticatorConfig::parse_set("  ").is_none());
    }

    // parse_algorithms tests

    #[test]
    fn parse_algorithms_parses_known_algorithms() {
        let algs = AuthenticatorConfig::parse_algorithms("HS256,RS256");
        assert!(algs.contains(&Algorithm::HS256));
        assert!(algs.contains(&Algorithm::RS256));
    }

    #[test]
    fn parse_algorithms_ignores_unknown() {
        let algs = AuthenticatorConfig::parse_algorithms("HS256,UNKNOWN,RS256");
        assert_eq!(algs.len(), 2);
        assert!(algs.contains(&Algorithm::HS256));
        assert!(algs.contains(&Algorithm::RS256));
    }

    #[test]
    fn parse_algorithms_returns_empty_for_empty_input() {
        let algs = AuthenticatorConfig::parse_algorithms("");
        assert!(algs.is_empty());
    }

    // AuthenticatorConfig::from_env_style_config tests

    #[test]
    fn config_new_requires_secret_when_no_jwks() {
        let result = AuthenticatorConfig::from_env_style_config(
            None::<&str>,
            "",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("shared secret"));
    }

    #[test]
    fn config_new_succeeds_with_secret() {
        let result = AuthenticatorConfig::from_env_style_config(
            Some("my-secret"),
            "HS256",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn config_new_fails_on_invalid_issuer_config() {
        let result = AuthenticatorConfig::from_env_style_config(
            Some("my-secret"),
            "",
            "https://issuer.example.com=invalid:config",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("invalid config"));
    }

    #[test]
    fn config_new_accepts_jwks_config() {
        let result = AuthenticatorConfig::from_env_style_config(
            None::<&str>,
            "",
            "https://issuer.example.com=jwks:/.well-known/jwks.json",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn config_new_accepts_mixed_issuer_configs() {
        let result = AuthenticatorConfig::from_env_style_config(
            Some("my-secret"),
            "",
            "https://iss1.example.com=secret,https://iss2.example.com=jwks:/jwks.json",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }

    // parse_jwt tests

    #[tokio::test]
    async fn parse_jwt_returns_claims_for_valid_token() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_NAME, CLAIM_SUB, CLAIM_TENANT};

        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_TENANT, "tenant-456")
            .with_string(CLAIM_NAME, "Test User")
            .into_token("test-secret")
            .unwrap();

        let authenticator = Authenticator::with_simple_secret("test-secret");
        let claims = authenticator.parse_jwt(&token).await.unwrap();

        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
        assert_eq!(claims.get(CLAIM_TENANT).unwrap(), &json!("tenant-456"));
        assert_eq!(claims.get(CLAIM_NAME).unwrap(), &json!("Test User"));
    }

    #[tokio::test]
    async fn parse_jwt_injects_default_locale() {
        use crate::web::auth::CLAIM_SUB;
        use crate::web::auth::user::tests::Builder;

        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .into_token("test-secret")
            .unwrap();

        let authenticator = Authenticator::with_simple_secret("test-secret");
        let claims = authenticator.parse_jwt(&token).await.unwrap();

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("en-US"));
    }

    #[tokio::test]
    async fn parse_jwt_fails_with_wrong_secret() {
        use crate::web::auth::CLAIM_SUB;
        use crate::web::auth::user::tests::Builder;

        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .into_token("correct-secret")
            .unwrap();

        let authenticator = Authenticator::with_simple_secret("wrong-secret");
        let result = authenticator.parse_jwt(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_jwt_fails_with_invalid_token() {
        let authenticator = Authenticator::with_simple_secret("test-secret");
        let result = authenticator.parse_jwt("not.a.valid-jwt").await;

        assert!(result.is_err());
    }

    // add_fetcher tests

    struct TestConfigFetcher {
        config: Arc<AuthenticatorConfig>,
        match_claim: String,
        match_value: String,
    }

    #[async_trait]
    impl ConfigFetcher for TestConfigFetcher {
        async fn fetch(&self, claims: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>> {
            if claims
                .get(&self.match_claim)
                .and_then(|v| v.as_str())
                .map(|v| v == self.match_value)
                .unwrap_or(false)
            {
                Some(self.config.clone())
            } else {
                None
            }
        }
    }

    #[tokio::test]
    async fn parse_jwt_uses_fetched_config_when_matched() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_SUB, CLAIM_TENANT};

        // Token signed with "fetcher-secret"
        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_TENANT, "special-tenant")
            .into_token("fetcher-secret")
            .unwrap();

        // Default authenticator uses "default-secret" (won't work for this token)
        let mut authenticator = Authenticator::with_simple_secret("default-secret");

        // Add fetcher that returns config with "fetcher-secret" for special-tenant
        let fetcher_config = Arc::new(
            AuthenticatorConfig::from_env_style_config(
                Some("fetcher-secret"),
                "",
                "",
                "",
                "de-DE".to_string(),
                None,
            )
            .unwrap(),
        );
        authenticator.add_fetcher(Box::new(TestConfigFetcher {
            config: fetcher_config,
            match_claim: CLAIM_TENANT.to_string(),
            match_value: "special-tenant".to_string(),
        }));

        // Should succeed because fetcher provides the correct secret
        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
        // Should use fetcher's default locale
        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("de-DE"));
    }

    #[tokio::test]
    async fn parse_jwt_falls_back_to_default_config_when_no_fetcher_matches() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_SUB, CLAIM_TENANT};

        // Token signed with "default-secret"
        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-456")
            .with_string(CLAIM_TENANT, "normal-tenant")
            .into_token("default-secret")
            .unwrap();

        let mut authenticator = Authenticator::with_simple_secret("default-secret");

        // Add fetcher that only matches "special-tenant"
        let fetcher_config = Arc::new(
            AuthenticatorConfig::from_env_style_config(
                Some("fetcher-secret"),
                "",
                "",
                "",
                "de-DE".to_string(),
                None,
            )
            .unwrap(),
        );
        authenticator.add_fetcher(Box::new(TestConfigFetcher {
            config: fetcher_config,
            match_claim: CLAIM_TENANT.to_string(),
            match_value: "special-tenant".to_string(),
        }));

        // Should succeed using default config (fetcher doesn't match)
        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-456"));
        // Should use default locale from default config
        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("en-US"));
    }

    #[tokio::test]
    async fn parse_jwt_fails_when_fetcher_matches_but_secret_wrong() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_SUB, CLAIM_TENANT};

        // Token signed with "actual-secret"
        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_TENANT, "special-tenant")
            .into_token("actual-secret")
            .unwrap();

        let mut authenticator = Authenticator::with_simple_secret("default-secret");

        // Fetcher returns config with wrong secret
        let fetcher_config = Arc::new(
            AuthenticatorConfig::from_env_style_config(
                Some("wrong-secret"),
                "",
                "",
                "",
                "de-DE".to_string(),
                None,
            )
            .unwrap(),
        );
        authenticator.add_fetcher(Box::new(TestConfigFetcher {
            config: fetcher_config,
            match_claim: CLAIM_TENANT.to_string(),
            match_value: "special-tenant".to_string(),
        }));

        // Should fail because fetcher's secret doesn't match
        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    // Multi-issuer tests

    #[tokio::test]
    async fn multi_issuer_shared_secret_accepts_valid_issuer() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer1.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://issuer1.example.com,https://issuer2.example.com",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
        assert_eq!(
            claims.get(CLAIM_ISS).unwrap(),
            &json!("https://issuer1.example.com")
        );
    }

    #[tokio::test]
    async fn multi_issuer_shared_secret_accepts_second_issuer() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer2.example.com")
            .with_string(CLAIM_SUB, "user-456")
            .into_token("shared-secret")
            .unwrap();

        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://issuer1.example.com,https://issuer2.example.com",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-456"));
    }

    #[tokio::test]
    async fn multi_issuer_rejects_unknown_issuer() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://unknown-issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://issuer1.example.com,https://issuer2.example.com",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    // Note: multi_issuer_rejects_token_without_issuer is not testable because
    // #[cfg(test)] clears required_spec_claims, disabling issuer requirement in tests.

    #[tokio::test]
    async fn per_issuer_strategy_with_mixed_config_accepts_secret_issuer() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        // Token from issuer that uses shared secret
        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://secret-issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        // Mixed config: one issuer uses secret, another uses jwks
        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://secret-issuer.example.com=secret,https://jwks-issuer.example.com=jwks:/.well-known/jwks.json",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
    }

    #[tokio::test]
    async fn per_issuer_strategy_rejects_unknown_issuer() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://unknown.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        // Mixed config triggers PerIssuer strategy
        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://secret-issuer.example.com=secret,https://jwks-issuer.example.com=jwks:/.well-known/jwks.json",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn algorithm_validation_rejects_wrong_algorithm() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        // Token uses HS256 (default in Builder)
        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        // Config only allows RS256
        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "RS256",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn algorithm_validation_accepts_correct_algorithm() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        // Token uses HS256
        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .into_token("shared-secret")
            .unwrap();

        // Config allows HS256 and RS256
        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "HS256,RS256",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
    }

    #[tokio::test]
    async fn audience_validation_accepts_valid_audience() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_AUD, CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_AUD, "my-api")
            .into_token("shared-secret")
            .unwrap();

        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://issuer.example.com",
            "my-api,other-api",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
    }

    #[tokio::test]
    async fn audience_validation_rejects_wrong_audience() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_AUD, CLAIM_ISS, CLAIM_SUB};

        let token = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer.example.com")
            .with_string(CLAIM_SUB, "user-123")
            .with_string(CLAIM_AUD, "wrong-api")
            .into_token("shared-secret")
            .unwrap();

        let config = AuthenticatorConfig::from_env_style_config(
            Some("shared-secret"),
            "",
            "https://issuer.example.com",
            "my-api",
            "en-US".to_string(),
            None,
        )
        .unwrap();
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    // Custom KeyFetcher tests (simulating JWKS)

    struct MockKeyFetcher {
        key: Arc<DecodingKey>,
        expected_kid: Option<String>,
    }

    impl MockKeyFetcher {
        fn new(secret: &[u8]) -> Self {
            Self {
                key: Arc::new(DecodingKey::from_secret(secret)),
                expected_kid: None,
            }
        }

        fn with_kid(mut self, kid: &str) -> Self {
            self.expected_kid = Some(kid.to_string());
            self
        }
    }

    #[async_trait]
    impl KeyFetcher for MockKeyFetcher {
        async fn fetch(&self, header: &Header) -> anyhow::Result<Arc<DecodingKey>> {
            if let Some(expected_kid) = &self.expected_kid
                && header.kid.as_ref() != Some(expected_kid)
            {
                anyhow::bail!(
                    "Key ID mismatch: expected {}, got {:?}",
                    expected_kid,
                    header.kid
                );
            }
            Ok(self.key.clone())
        }
    }

    /// Creates a test configuration with a custom key fetcher for a given issuer.
    fn create_custom_key_fetcher_config(
        issuer: &str,
        key_fetcher: Arc<dyn KeyFetcher>,
        default_locale: String,
    ) -> AuthenticatorConfig {
        AuthenticatorConfig::new(
            None,
            [issuer.to_owned()].into(),
            None,
            default_locale,
            None,
            key_fetcher,
            None,
        )
    }

    #[tokio::test]
    async fn custom_key_fetcher_validates_token() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let issuer = "https://custom-idp.example.com";

        // Create token signed with our "JWKS" secret
        let token = Builder::new()
            .with_string(CLAIM_ISS, issuer)
            .with_string(CLAIM_SUB, "user-from-jwks")
            .into_token("jwks-secret-key")
            .unwrap();

        // Create authenticator with mock key fetcher
        let key_fetcher = Arc::new(MockKeyFetcher::new(b"jwks-secret-key"));
        let config = create_custom_key_fetcher_config(issuer, key_fetcher, "en-US".to_string());
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-from-jwks"));
    }

    #[tokio::test]
    async fn custom_key_fetcher_rejects_wrong_key() {
        use crate::web::auth::user::tests::Builder;
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};

        let issuer = "https://custom-idp.example.com";

        // Create token signed with different secret
        let token = Builder::new()
            .with_string(CLAIM_ISS, issuer)
            .with_string(CLAIM_SUB, "user-from-jwks")
            .into_token("actual-secret")
            .unwrap();

        // Key fetcher returns different key
        let key_fetcher = Arc::new(MockKeyFetcher::new(b"wrong-secret"));
        let config = create_custom_key_fetcher_config(issuer, key_fetcher, "en-US".to_string());
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn custom_key_fetcher_can_validate_kid() {
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};
        use jsonwebtoken::{EncodingKey, encode};
        use std::time::{SystemTime, UNIX_EPOCH};

        let issuer = "https://custom-idp.example.com";

        // Create token with kid in header
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("key-123".to_string());

        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let mut claims = std::collections::HashMap::new();
        claims.insert(CLAIM_ISS.to_string(), json!(issuer));
        claims.insert(CLAIM_SUB.to_string(), json!("user-with-kid"));
        claims.insert("exp".to_string(), json!(exp));

        let token = encode(&header, &claims, &EncodingKey::from_secret(b"jwks-secret")).unwrap();

        // Key fetcher expects specific kid
        let key_fetcher = Arc::new(MockKeyFetcher::new(b"jwks-secret").with_kid("key-123"));
        let config = create_custom_key_fetcher_config(issuer, key_fetcher, "en-US".to_string());
        let authenticator = Authenticator::new(config);

        let claims = authenticator.parse_jwt(&token).await.unwrap();
        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-with-kid"));
    }

    #[tokio::test]
    async fn custom_key_fetcher_rejects_wrong_kid() {
        use crate::web::auth::{CLAIM_ISS, CLAIM_SUB};
        use jsonwebtoken::{EncodingKey, encode};
        use std::time::{SystemTime, UNIX_EPOCH};

        let issuer = "https://custom-idp.example.com";

        // Create token with kid in header
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("wrong-key-id".to_string());

        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let mut claims = std::collections::HashMap::new();
        claims.insert(CLAIM_ISS.to_string(), json!(issuer));
        claims.insert(CLAIM_SUB.to_string(), json!("user-with-kid"));
        claims.insert("exp".to_string(), json!(exp));

        let token = encode(&header, &claims, &EncodingKey::from_secret(b"jwks-secret")).unwrap();

        // Key fetcher expects different kid
        let key_fetcher = Arc::new(MockKeyFetcher::new(b"jwks-secret").with_kid("expected-key-id"));
        let config = create_custom_key_fetcher_config(issuer, key_fetcher, "en-US".to_string());
        let authenticator = Authenticator::new(config);

        let result = authenticator.parse_jwt(&token).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Key ID mismatch")
        );
    }

    // Expiration tests

    #[tokio::test]
    async fn parse_jwt_rejects_expired_token() {
        use crate::web::auth::CLAIM_SUB;
        use crate::web::auth::user::tests::Builder;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create token that expired 1 hour ago
        let expired_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;

        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_value("exp", json!(expired_exp))
            .into_token("test-secret")
            .unwrap();

        let authenticator = Authenticator::with_simple_secret("test-secret");
        let result = authenticator.parse_jwt(&token).await;

        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("exp") || err_msg.contains("Expired"),
            "Expected error about expiration, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn parse_jwt_accepts_token_not_yet_expired() {
        use crate::web::auth::CLAIM_SUB;
        use crate::web::auth::user::tests::Builder;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create token that expires in 1 hour
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let token = Builder::new()
            .with_string(CLAIM_SUB, "user-123")
            .with_value("exp", json!(future_exp))
            .into_token("test-secret")
            .unwrap();

        let authenticator = Authenticator::with_simple_secret("test-secret");
        let claims = authenticator.parse_jwt(&token).await.unwrap();

        assert_eq!(claims.get(CLAIM_SUB).unwrap(), &json!("user-123"));
    }
}
