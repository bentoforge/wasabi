//! GitHub Actions OIDC authentication.
//!
//! Provides a [`ConfigFetcher`] implementation
//! for authenticating GitHub Actions workflow tokens. Validates that tokens come from allowed
//! repositories using regex matching.
//!
//! # Example
//!
//! ```ignore
//! use wasabi_core::web::auth::authenticator::Authenticator;
//! use wasabi_core::web::auth::github_oidc::GithubOidcConfigFetcher;
//!
//! let mut auth = Authenticator::from_env()?;
//! GithubOidcConfigFetcher::install(&mut auth)?;
//! ```
//!
//! # Environment Variables
//!
//! - `GITHUB_OIDC_ALLOWED_REPOS` - Regex pattern for allowed repositories (e.g., `myorg/.*`)
//! - `GITHUB_OIDC_CLAIM_MAPPING` - Optional claim transformation rules

use crate::web::auth::authenticator::{
    Authenticator, AuthenticatorConfig, ConfigFetcher, JwksFetcher,
};
use crate::web::auth::claim_transformer::ClaimTransformer;
use crate::web::auth::user::ClaimsSet;
use crate::web::auth::{CLAIM_ISS, DEFAULT_LOCALE};
use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use std::env;
use std::sync::Arc;

/// GitHub's OIDC token issuer URL.
const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Claim containing the full repository name (e.g., `owner/repo`).
const CLAIM_REPOSITORY: &str = "repository";

fn create_github_oidc_config(claim_transformer: Option<ClaimTransformer>) -> AuthenticatorConfig {
    let jwks_url = format!("{}/.well-known/jwks", GITHUB_OIDC_ISSUER);

    AuthenticatorConfig::new(
        Some("RS256"),
        [GITHUB_OIDC_ISSUER.to_owned()].into(),
        env::var("AUTH_AUDIENCE").ok().as_deref(),
        DEFAULT_LOCALE.to_string(),
        None,
        Arc::new(JwksFetcher::new(jwks_url)),
        claim_transformer,
    )
}

/// Config fetcher for GitHub Actions OIDC tokens.
///
/// Validates that tokens are from GitHub Actions and that the repository
/// matches the configured pattern.
pub struct GithubOidcConfigFetcher {
    allowed_repos_pattern: Regex,
    config: Arc<AuthenticatorConfig>,
}

impl std::fmt::Debug for GithubOidcConfigFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubOidcConfigFetcher")
            .field(
                "allowed_repos_pattern",
                &self.allowed_repos_pattern.as_str(),
            )
            .finish()
    }
}

impl GithubOidcConfigFetcher {
    /// Creates a new fetcher with the given repository pattern.
    ///
    /// The pattern is automatically anchored with `^` and `$` if not already present
    /// to prevent partial matches (e.g., `myorg/.*` won't match `attacker/myorg/repo`).
    ///
    /// # Arguments
    ///
    /// * `allowed_repos_pattern` - Regex pattern for allowed repositories
    /// * `claim_transformer` - Optional claim transformation rules
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid.
    pub fn new(
        allowed_repos_pattern: &str,
        claim_transformer: Option<ClaimTransformer>,
    ) -> anyhow::Result<Self> {
        let anchored_pattern = Self::ensure_anchored(allowed_repos_pattern);
        let regex = Regex::new(&anchored_pattern).map_err(|e| {
            anyhow::anyhow!(
                "Invalid repository pattern '{}': {}",
                allowed_repos_pattern,
                e
            )
        })?;

        let config = Arc::new(create_github_oidc_config(claim_transformer));

        Ok(Self {
            allowed_repos_pattern: regex,
            config,
        })
    }

    /// Installs GitHub OIDC authentication if configured via environment variables.
    ///
    /// This is a convenience method that combines [`from_env`](Self::from_env) and
    /// [`Authenticator::add_fetcher`](crate::web::auth::authenticator::Authenticator::add_fetcher).
    ///
    /// Does nothing if `GITHUB_OIDC_ALLOWED_REPOS` is not set.
    ///
    /// # Environment Variables
    ///
    /// - `GITHUB_OIDC_ALLOWED_REPOS` - Regex pattern for allowed repositories
    /// - `GITHUB_OIDC_CLAIM_MAPPING` - Optional claim transformation rules
    #[tracing::instrument(skip(authenticator))]
    pub fn install(authenticator: &mut Authenticator) -> anyhow::Result<()> {
        if let Some(fetcher) = Self::from_env()? {
            tracing::info!(pattern = %fetcher.allowed_repos_pattern, "GitHub OIDC authentication enabled");
            authenticator.add_fetcher(Box::new(fetcher));
        } else {
            tracing::info!("GitHub OIDC authentication not configured");
        }
        Ok(())
    }

    /// Creates a fetcher from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `GITHUB_OIDC_ALLOWED_REPOS` - Required regex pattern for allowed repositories
    /// - `GITHUB_OIDC_CLAIM_MAPPING` - Optional claim transformation rules
    ///
    /// # Returns
    ///
    /// - `Ok(Some(fetcher))` if `GITHUB_OIDC_ALLOWED_REPOS` is set
    /// - `Ok(None)` if `GITHUB_OIDC_ALLOWED_REPOS` is not set
    /// - `Err` if the pattern is invalid or claim mapping parsing fails
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let allowed_repos = match env::var("GITHUB_OIDC_ALLOWED_REPOS") {
            Ok(pattern) if !pattern.is_empty() => pattern,
            _ => return Ok(None),
        };

        let claim_transformer = match env::var("GITHUB_OIDC_CLAIM_MAPPING") {
            Ok(mapping) if !mapping.is_empty() => Some(ClaimTransformer::parse(&mapping)?),
            _ => None,
        };

        Self::new(&allowed_repos, claim_transformer).map(Some)
    }

    /// Ensures the pattern is anchored with `^` at start and `$` at end.
    fn ensure_anchored(pattern: &str) -> String {
        let mut result = pattern.to_string();

        if !result.starts_with('^') {
            result.insert(0, '^');
        }

        if !result.ends_with('$') {
            result.push('$');
        }

        result
    }

    /// Checks if the repository claim matches the allowed pattern.
    fn matches_repository(&self, claims: &ClaimsSet) -> bool {
        claims
            .get(CLAIM_REPOSITORY)
            .and_then(Value::as_str)
            .map(|repo| self.allowed_repos_pattern.is_match(repo))
            .unwrap_or(false)
    }
}

#[async_trait]
impl ConfigFetcher for GithubOidcConfigFetcher {
    async fn fetch(&self, claims: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>> {
        // Check if this is a GitHub OIDC token
        let issuer = claims.get(CLAIM_ISS).and_then(Value::as_str)?;

        if issuer != GITHUB_OIDC_ISSUER {
            return None;
        }

        // Check if the repository matches our pattern
        if !self.matches_repository(claims) {
            return None;
        }

        Some(self.config.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims_with(iss: &str, repo: &str) -> ClaimsSet {
        let mut claims = ClaimsSet::new();
        claims.insert(CLAIM_ISS.to_string(), json!(iss));
        claims.insert(CLAIM_REPOSITORY.to_string(), json!(repo));
        claims
    }

    #[tokio::test]
    async fn fetch_returns_none_for_non_github_issuer() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();
        let claims = claims_with("https://other-issuer.com", "myorg/repo");

        let result = fetcher.fetch(&claims).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_none_for_non_matching_repo() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();
        let claims = claims_with(GITHUB_OIDC_ISSUER, "otherorg/repo");

        let result = fetcher.fetch(&claims).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_config_for_matching_repo() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();
        let claims = claims_with(GITHUB_OIDC_ISSUER, "myorg/repo");

        let result = fetcher.fetch(&claims).await;

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn fetch_matches_exact_repo() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/specific-repo", None).unwrap();

        let matching = claims_with(GITHUB_OIDC_ISSUER, "myorg/specific-repo");
        let non_matching = claims_with(GITHUB_OIDC_ISSUER, "myorg/other-repo");

        assert!(fetcher.fetch(&matching).await.is_some());
        assert!(fetcher.fetch(&non_matching).await.is_none());
    }

    #[tokio::test]
    async fn fetch_matches_multiple_repos_with_alternation() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/(api|web)", None).unwrap();

        let api = claims_with(GITHUB_OIDC_ISSUER, "myorg/api");
        let web = claims_with(GITHUB_OIDC_ISSUER, "myorg/web");
        let other = claims_with(GITHUB_OIDC_ISSUER, "myorg/cli");

        assert!(fetcher.fetch(&api).await.is_some());
        assert!(fetcher.fetch(&web).await.is_some());
        assert!(fetcher.fetch(&other).await.is_none());
    }

    #[test]
    fn regex_auto_anchors_pattern() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();

        // The pattern should be anchored, preventing prefix attacks
        assert!(fetcher.allowed_repos_pattern.is_match("myorg/repo"));
        assert!(
            !fetcher
                .allowed_repos_pattern
                .is_match("attacker/myorg/repo")
        );
        // Note: myorg/.* DOES match myorg/repo/subpath because .* matches any chars
        assert!(fetcher.allowed_repos_pattern.is_match("myorg/repo/subpath"));
    }

    #[test]
    fn regex_exact_match_rejects_subpaths() {
        // Use exact pattern without wildcard to reject subpaths
        let fetcher = GithubOidcConfigFetcher::new("myorg/repo", None).unwrap();

        assert!(fetcher.allowed_repos_pattern.is_match("myorg/repo"));
        assert!(!fetcher.allowed_repos_pattern.is_match("myorg/repo/subpath"));
    }

    #[test]
    fn regex_does_not_double_anchor() {
        let fetcher = GithubOidcConfigFetcher::new("^myorg/.*$", None).unwrap();

        // Should not have double anchors
        assert_eq!(fetcher.allowed_repos_pattern.as_str(), "^myorg/.*$");
    }

    #[tokio::test]
    async fn fetch_rejects_partial_match_without_anchors() {
        // This tests the security feature: even without explicit anchors in the input,
        // the pattern should be anchored to prevent attacks like "attacker/myorg/repo"
        let fetcher = GithubOidcConfigFetcher::new("myorg/repo", None).unwrap();

        let exact_match = claims_with(GITHUB_OIDC_ISSUER, "myorg/repo");
        let partial_match_prefix = claims_with(GITHUB_OIDC_ISSUER, "attacker/myorg/repo");
        let partial_match_suffix = claims_with(GITHUB_OIDC_ISSUER, "myorg/repo-extended");

        assert!(fetcher.fetch(&exact_match).await.is_some());
        assert!(fetcher.fetch(&partial_match_prefix).await.is_none());
        assert!(fetcher.fetch(&partial_match_suffix).await.is_none());
    }

    #[test]
    fn new_fails_for_invalid_regex() {
        let result = GithubOidcConfigFetcher::new("[invalid(", None);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid repository pattern")
        );
    }

    #[tokio::test]
    async fn fetch_returns_none_when_repository_claim_missing() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();

        let mut claims = ClaimsSet::new();
        claims.insert(CLAIM_ISS.to_string(), json!(GITHUB_OIDC_ISSUER));
        // No repository claim

        let result = fetcher.fetch(&claims).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_none_when_issuer_claim_missing() {
        let fetcher = GithubOidcConfigFetcher::new("myorg/.*", None).unwrap();

        let mut claims = ClaimsSet::new();
        claims.insert(CLAIM_REPOSITORY.to_string(), json!("myorg/repo"));
        // No issuer claim

        let result = fetcher.fetch(&claims).await;

        assert!(result.is_none());
    }
}
