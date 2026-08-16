//! Permission-string expression evaluation.
//!
//! A tiny boolean grammar over permission strings, used both to guard routes
//! (via [`with_user_with`](super::with_user_with)) and by token issuers to
//! project permissions. The grammar is intentionally minimal:
//!
//! - `,` — OR (lowest precedence): `a,b` holds if `a` or `b` holds.
//! - `+` — AND: `a+b` holds if both `a` and `b` hold.
//! - `!` — NOT (prefix on a term): `!a` holds if `a` does **not** hold.
//! - whitespace around terms/operators is ignored.
//!
//! An **empty** expression holds (no restriction); an empty clause is skipped.
//!
//! # Examples
//!
//! ```
//! use wasabi_core::web::auth::permission_expr::eval_permission_expr;
//! use std::collections::HashSet;
//!
//! let granted: HashSet<&str> = ["manage:users", "write:usage"].into_iter().collect();
//! let has = |p: &str| granted.contains(p);
//!
//! assert!(eval_permission_expr("manage:users", has));
//! assert!(eval_permission_expr("admin:system, manage:users", has)); // OR
//! assert!(eval_permission_expr("manage:users + write:usage", has));  // AND
//! assert!(eval_permission_expr("manage:users + !self:readonly", has)); // NOT
//! assert!(!eval_permission_expr("manage:users + self:readonly", has));
//! assert!(eval_permission_expr("", has)); // empty = no restriction
//! ```

/// Evaluates a permission-string `expression` against a membership predicate.
///
/// `contains(term)` must return whether `term` is present in the set being tested
/// (e.g. the token's granted permissions, or an issuer's accumulated subject set).
/// See the [module docs](self) for the grammar.
pub fn eval_permission_expr(expression: &str, contains: impl Fn(&str) -> bool) -> bool {
    let clauses: Vec<&str> = expression
        .split(',')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect();
    if clauses.is_empty() {
        return true;
    }
    clauses.iter().any(|clause| {
        let terms: Vec<&str> = clause
            .split('+')
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .collect();
        !terms.is_empty()
            && terms.iter().all(|term| match term.strip_prefix('!') {
                Some(negated) => !contains(negated.trim()),
                None => contains(term),
            })
    })
}

#[cfg(test)]
mod tests {
    use super::eval_permission_expr;
    use std::collections::HashSet;

    fn has(set: &[&str]) -> impl Fn(&str) -> bool {
        let set: HashSet<String> = set.iter().map(|term| (*term).to_owned()).collect();
        move |term: &str| set.contains(term)
    }

    #[test]
    fn or_and_not_precedence() {
        // a OR (b AND c)
        assert!(eval_permission_expr("a,b+c", has(&["a"])));
        assert!(eval_permission_expr("a,b+c", has(&["b", "c"])));
        assert!(!eval_permission_expr("a,b+c", has(&["b"])));
        assert!(!eval_permission_expr("a,b+c", has(&["x"])));
    }

    #[test]
    fn negation() {
        assert!(eval_permission_expr("a+!b", has(&["a"])));
        assert!(!eval_permission_expr("a+!b", has(&["a", "b"])));
        assert!(eval_permission_expr("!b", has(&["a"])));
        assert!(!eval_permission_expr("!b", has(&["b"])));
    }

    #[test]
    fn whitespace_and_empty() {
        assert!(eval_permission_expr("  a + !b ", has(&["a"])));
        assert!(eval_permission_expr("", has(&["a"])));
        assert!(eval_permission_expr("   ", has(&[])));
    }
}
