//! Authenticated user representation with claim accessors.
//!
//! The [`User`] struct wraps validated JWT claims and provides typed access
//! to standard fields like tenant, user ID, name, email, and permissions.

use crate::status_bail;
use crate::web::auth::permission_expr::eval_permission_expr;
use crate::web::auth::{
    CLAIM_ACT, CLAIM_EMAIL, CLAIM_ISS, CLAIM_LOCALE, CLAIM_NAME, CLAIM_PERMISSIONS, CLAIM_SUB,
    CLAIM_TENANT, DEFAULT_LOCALE,
};
use crate::web::error::ResultExt;
use crate::web::validation::{is_valid_id, is_valid_str};
use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::http::StatusCode;

pub(crate) type ClaimsSet = BTreeMap<String, Value>;

/// An authenticated user extracted from a validated JWT.
#[derive(Clone)]
pub struct User {
    /// The original JWT token string.
    pub jwt_token: String,
    pub(crate) claims: ClaimsSet,
}

impl User {
    /// Returns the tenant ID from the `tenant` claim.
    pub fn tenant_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_TENANT)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid  tenant id ('tenant') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the token issuer from the `iss` claim.
    pub fn issuer(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_ISS)
            .and_then(Value::as_str)
            .filter(|iss| is_valid_str(iss, 1, 512))
            .context("No or invalid issuer ('iss') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user ID from the `sub` claim.
    pub fn user_id(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_SUB)
            .and_then(Value::as_str)
            .filter(|id| is_valid_id(id))
            .context("No or invalid auth id ('sub') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user's full name from the `name` claim.
    pub fn full_name(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_NAME)
            .and_then(Value::as_str)
            .filter(|name| is_valid_str(name, 1, 512))
            .context("No or invalid auth name ('name') in JWT token present!")
            .mark_client_error()
    }

    /// Returns the user's email from the `email` claim.
    pub fn email(&self) -> anyhow::Result<&str> {
        self.claims
            .get(CLAIM_EMAIL)
            .and_then(Value::as_str)
            .filter(|email| is_valid_str(email, 1, 512))
            .context("No or invalid email ('email') in JWT token present!")
            .mark_client_error()
    }

    /// Returns a raw claim value by name, if present. Escape hatch for application-specific claims
    /// beyond the typed accessors above (e.g. an `amr` / auth-strength claim carried by the issuer).
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }

    /// Returns `true` if the user has at least one of the given permissions.
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        if let Some(granted_permission) = self
            .claims
            .get(CLAIM_PERMISSIONS)
            .and_then(|permissions| permissions.as_array())
        {
            let granted_permissions = granted_permission
                .iter()
                .filter_map(|permission| permission.as_str().map(str::to_owned))
                .collect::<HashSet<String>>();
            permissions
                .iter()
                .any(|expected_permission| granted_permissions.contains(*expected_permission))
        } else {
            false
        }
    }

    /// Returns the user if they have at least one of the given permissions, otherwise 401.
    #[expect(clippy::indexing_slicing, reason = "length checked to be 1")]
    pub fn enforce_any_permission(self, permissions: &[&str]) -> anyhow::Result<Self> {
        if self.has_any_permission(permissions) {
            Ok(self)
        } else if permissions.len() == 1 {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The permission '{}' is required for this action",
                permissions[0]
            );
        } else {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "One of the permissions '{}' is required for this action",
                permissions.join(", ")
            );
        }
    }

    /// Returns `true` if the user's granted permissions satisfy the boolean permission-string
    /// `expression` (`,` = OR, `+` = AND, `!` = NOT; empty = no restriction). See
    /// [`permission_expr`](crate::web::auth::permission_expr).
    pub fn has_permission_expr(&self, expression: &str) -> bool {
        let granted: HashSet<&str> = self
            .claims
            .get(CLAIM_PERMISSIONS)
            .and_then(Value::as_array)
            .map(|permissions| {
                permissions
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<HashSet<&str>>()
            })
            .unwrap_or_default();
        eval_permission_expr(expression, |term| granted.contains(term))
    }

    /// Returns the user if their permissions satisfy `expression`, otherwise 401.
    pub fn enforce_permission_expr(self, expression: &str) -> anyhow::Result<Self> {
        if self.has_permission_expr(expression) {
            Ok(self)
        } else {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "The permission expression '{}' must be satisfied for this action",
                expression
            );
        }
    }

    /// Returns the end-auth's locale, represented as a BCP47 (RFC5646) language tag.
    ///
    /// This is typically an ISO 639 Alpha-2 (ISO639) language code in lowercase and an ISO 3166-1
    /// Alpha-2 (ISO3166‑1) country code in uppercase, separated by a dash. For example, en-US or
    /// fr-CA.
    ///
    /// This uses the claim [CLAIM_LOCALE] ("locale") as defined by OpenID Connect Core 1.0,
    /// Section 5.1.
    ///
    /// The claim is always present: [`Authenticator`](crate::web::auth::authenticator::Authenticator)
    /// injects one at validation time for a token that carries none — negotiated from the request's
    /// `Accept-Language` against the configured supported languages, else the deployment default. So
    /// this stays a single claim read while still answering in the caller's own language.
    pub fn locale(&self) -> &str {
        self.claims
            .get(CLAIM_LOCALE)
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_LOCALE)
    }

    /// Returns a [`UserBuilder`] for constructing a `User` from individual claims.
    ///
    /// Primarily intended for tests (and internal callers) that already have
    /// validated claims and want to exercise the accessors — or produce a signed
    /// token via [`UserBuilder::into_token`] — without going through JWT parsing.
    pub fn builder() -> UserBuilder {
        UserBuilder::new()
    }
}

/// Fluent builder for constructing a [`User`] from individual claims.
///
/// This assembles a claim set directly, bypassing JWT validation, which makes it
/// convenient for tests that need a `User` with specific claims. A fresh builder
/// already carries an `exp` claim one hour in the future.
pub struct UserBuilder {
    jwt_token: String,
    claims: ClaimsSet,
}

impl UserBuilder {
    /// Creates a new builder with an `exp` claim set to one hour from now.
    pub fn new() -> Self {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since_epoch| since_epoch.as_secs())
            .unwrap_or_default()
            + 3600;

        let mut claims = ClaimsSet::new();
        let _ = claims.insert("exp".to_owned(), Value::from(exp));

        UserBuilder {
            jwt_token: String::new(),
            claims,
        }
    }

    /// Sets a string claim.
    pub fn with_string(mut self, key: &str, value: &str) -> Self {
        let _ = self.claims.insert(key.to_owned(), Value::from(value));
        self
    }

    /// Sets an arbitrary JSON claim.
    pub fn with_value(mut self, key: &str, value: Value) -> Self {
        let _ = self.claims.insert(key.to_owned(), value);
        self
    }

    /// Builds the [`User`] from the accumulated claims.
    pub fn build(self) -> User {
        User {
            jwt_token: self.jwt_token,
            claims: self.claims,
        }
    }

    /// Signs the accumulated claims into a JWT string using the given HS256 secret.
    pub fn into_token(self, secret: &str) -> anyhow::Result<String> {
        encode(
            &Header::new(Algorithm::HS256),
            &self.claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .context("Signing failed")
    }
}

impl Default for UserBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn fmt_act(act: &Value, mut buffer: String) -> String {
            if act.is_object() {
                if let Some(sub) = act.get(CLAIM_SUB).and_then(Value::as_str) {
                    if !buffer.is_empty() {
                        buffer.push_str(", ")
                    }
                    buffer.push_str(sub);

                    if let Some(tenant) = act.get(CLAIM_TENANT).and_then(Value::as_str) {
                        buffer.push_str(" (tenant: ");
                        buffer.push_str(tenant);
                        buffer.push(')');
                    }
                }

                if let Some(act) = act.get(CLAIM_ACT) {
                    buffer = fmt_act(act, buffer);
                }
            } else if act.is_string() {
                buffer.push_str(act.as_str().unwrap_or_default());
            } else {
                buffer.push_str(&act.to_string());
            }

            buffer
        }

        if let Some(act) = self.claims.get(CLAIM_ACT) {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"sub\": \"{}\", \"act\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
                fmt_act(act, String::new())
            )
        } else {
            write!(
                f,
                "{{\"tenant\": \"{}\", \"sub\": \"{}\" }}",
                self.tenant_id().unwrap_or("?"),
                self.user_id().unwrap_or("?"),
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::web::auth::*;
    use serde_json::json;

    // The former in-module test `Builder` is now the public `UserBuilder`. The
    // alias keeps the existing test call sites (here and in sibling modules that
    // import `user::tests::Builder`) working unchanged.
    pub(crate) use super::UserBuilder as Builder;

    #[test]
    fn simple_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .build();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\" }"
        );
    }

    #[test]
    fn simple_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_string(CLAIM_ACT, "sub1")
            .build();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1\" }"
        );

        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!(42))
            .build();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"42\" }"
        );
    }

    #[test]
    fn complex_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!({"sub": "sub1", "tenant": "tenant2"}))
            .build();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1 (tenant: tenant2)\" }"
        );
    }

    #[test]
    fn chained_delegate_user_debug_formatting() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "1234")
            .with_string(CLAIM_TENANT, "0815")
            .with_value(CLAIM_ACT, json!({"sub": "sub1", "act": {"sub": "sub2"}}))
            .build();

        assert_eq!(
            format!("{:?}", user),
            "{\"tenant\": \"0815\", \"sub\": \"1234\", \"act\": \"sub1, sub2\" }"
        );
    }

    #[test]
    fn user_tenant_id_returns_valid_tenant_id() {
        let user = Builder::new().with_string(CLAIM_TENANT, "0815").build();

        assert_eq!(user.tenant_id().unwrap(), "0815");
    }

    #[test]
    fn user_tenant_id_fails_for_missing_tenant_id() {
        let user = Builder::new().build();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_issuer_returns_valid_issuer() {
        let user = Builder::new()
            .with_string(CLAIM_ISS, "https://issuer.example.com")
            .build();

        assert_eq!(user.issuer().unwrap(), "https://issuer.example.com");
    }

    #[test]
    fn user_issuer_fails_for_missing_issuer() {
        let user = Builder::new().build();
        assert!(user.issuer().is_err());
    }

    #[test]
    fn user_issuer_fails_for_empty_issuer() {
        let user = Builder::new().with_string(CLAIM_ISS, "").build();
        assert!(user.issuer().is_err());
    }

    #[test]
    fn user_tenant_id_fails_for_empty_tenant_id() {
        let user = Builder::new().with_string(CLAIM_TENANT, "").build();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_tenant_id_fails_for_tenant_id_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_TENANT, "a".repeat(65).as_str())
            .build();
        assert!(user.tenant_id().is_err());
    }

    #[test]
    fn user_user_id_returns_valid_user_id() {
        let user = Builder::new().with_string(CLAIM_SUB, "1234").build();

        assert_eq!(user.user_id().unwrap(), "1234");
    }

    #[test]
    fn user_user_id_fails_for_missing_user_id() {
        let user = Builder::new().build();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_user_id_fails_for_empty_user_id() {
        let user = Builder::new().with_string(CLAIM_SUB, "").build();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_user_id_fails_for_user_id_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_SUB, "a".repeat(65).as_str())
            .build();
        assert!(user.user_id().is_err());
    }

    #[test]
    fn user_full_name_returns_valid_name() {
        let user = Builder::new().with_string(CLAIM_NAME, "John Doe").build();

        assert_eq!(user.full_name().unwrap(), "John Doe");
    }

    #[test]
    fn user_full_name_fails_for_missing_name() {
        let user = Builder::new().build();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_full_name_fails_for_empty_name() {
        let user = Builder::new().with_string(CLAIM_NAME, "").build();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_full_name_fails_for_name_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_NAME, "a".repeat(513).as_str())
            .build();
        assert!(user.full_name().is_err());
    }

    #[test]
    fn user_email_returns_valid_email() {
        let user = Builder::new()
            .with_string(CLAIM_EMAIL, "auth@example.com")
            .build();

        assert_eq!(user.email().unwrap(), "auth@example.com");
    }

    #[test]
    fn user_email_fails_for_missing_email() {
        let user = Builder::new().build();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_email_fails_for_empty_email() {
        let user = Builder::new().with_string(CLAIM_EMAIL, "").build();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_email_fails_for_email_exceeding_max_length() {
        let user = Builder::new()
            .with_string(CLAIM_EMAIL, "a".repeat(513).as_str())
            .build();
        assert!(user.email().is_err());
    }

    #[test]
    fn user_has_permission_returns_true_if_user_has_permission() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build();

        assert!(user.has_any_permission(&["permission1"]));
        assert!(user.has_any_permission(&["permission2"]));
        assert!(user.has_any_permission(&["permission1", "permission2"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_user_does_not_have_permission() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build();

        assert!(!user.has_any_permission(&["permission3"]));
        assert!(!user.has_any_permission(&["permission4"]));
        assert!(!user.has_any_permission(&["permission3", "permission4"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_no_permissions_claim_present() {
        let user = Builder::new().build();

        assert!(!user.has_any_permission(&["permission1"]));
    }

    #[test]
    fn user_has_permission_returns_false_if_permissions_claim_is_not_an_array() {
        let user = Builder::new()
            .with_string(CLAIM_PERMISSIONS, "permission1")
            .build();

        assert!(!user.has_any_permission(&["permission1"]));
    }

    #[test]
    fn user_enforce_permission_with_permission_succeeds() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build();

        assert!(
            user.clone()
                .enforce_any_permission(&["permission1"])
                .is_ok()
        );
        assert!(
            user.clone()
                .enforce_any_permission(&["permission2"])
                .is_ok()
        );
        assert!(
            user.enforce_any_permission(&["permissionX", "permission1"])
                .is_ok()
        );
    }

    #[test]
    fn user_enforce_permission_fails_if_permission_is_missing() {
        let user = Builder::new()
            .with_value(CLAIM_PERMISSIONS, json!(["permission1", "permission2"]))
            .build();

        assert_eq!(
            user.clone()
                .enforce_any_permission(&["permissionA"])
                .unwrap_err()
                .to_string(),
            "The permission 'permissionA' is required for this action"
        );

        assert_eq!(
            user.enforce_any_permission(&["permissionA", "permissionB"])
                .unwrap_err()
                .to_string(),
            "One of the permissions 'permissionA, permissionB' is required for this action"
        );
    }
}
