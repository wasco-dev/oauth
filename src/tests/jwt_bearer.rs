use super::{now_secs, AUD, ISS, SCOPE};
use crate::sign::make_jwt_bearer_claims;

// ---------------------------------------------------------------------------
// Timestamp tests
// ---------------------------------------------------------------------------

#[test]
fn iat_is_current_time() {
    let before = now_secs();
    let claims = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), None, None);
    let after = now_secs();
    assert!(
        claims.iat >= before && claims.iat <= after,
        "iat ({}) not in [{before}, {after}]",
        claims.iat
    );
}

#[test]
fn exp_equals_iat_plus_default_duration() {
    let claims = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), None, None);
    assert_eq!(
        claims.exp,
        claims.iat + 3600,
        "default expiry should be 3600 seconds"
    );
}

#[test]
fn exp_equals_iat_plus_custom_duration() {
    let claims = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), Some(300), None);
    assert_eq!(claims.exp, claims.iat + 300);
}

#[test]
fn explicit_3600_matches_default() {
    let default = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), None, None);
    let explicit = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), Some(3600), None);
    // Both should produce the same duration offset (iat may differ by ≤1s, so check offsets)
    assert_eq!(explicit.exp - explicit.iat, default.exp - default.iat);
}

// ---------------------------------------------------------------------------
// Field assignment tests
// ---------------------------------------------------------------------------

#[test]
fn all_fields_assigned_correctly() {
    let claims = make_jwt_bearer_claims(
        ISS.into(),
        SCOPE.into(),
        AUD.into(),
        Some(3600),
        Some(ISS.into()),
    );
    assert_eq!(claims.issuer, ISS);
    assert_eq!(claims.scope, SCOPE);
    assert_eq!(claims.audience, AUD);
    assert_eq!(claims.subject.as_deref(), Some(ISS));
}

#[test]
fn subject_none_when_not_provided() {
    let claims = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), None, None);
    assert!(claims.subject.is_none());
}

#[test]
fn subject_some_when_provided() {
    let subject = "delegate@example.com";
    let claims = make_jwt_bearer_claims(
        ISS.into(),
        SCOPE.into(),
        AUD.into(),
        None,
        Some(subject.into()),
    );
    assert_eq!(claims.subject.as_deref(), Some(subject));
}

// ---------------------------------------------------------------------------
// Scope normalisation tests
// ---------------------------------------------------------------------------

#[test]
fn scope_single_value_unchanged() {
    let claims = make_jwt_bearer_claims(ISS.into(), SCOPE.into(), AUD.into(), None, None);
    assert_eq!(claims.scope, SCOPE);
}

#[test]
fn scope_comma_separated_normalised_to_space() {
    let claims = make_jwt_bearer_claims(
        ISS.into(),
        "openid,email,profile".into(),
        AUD.into(),
        None,
        None,
    );
    assert_eq!(claims.scope, "openid email profile");
}

#[test]
fn scope_comma_with_surrounding_spaces_trimmed() {
    let claims = make_jwt_bearer_claims(
        ISS.into(),
        "openid , email , profile".into(),
        AUD.into(),
        None,
        None,
    );
    assert_eq!(claims.scope, "openid email profile");
}

#[test]
fn scope_already_space_separated_preserved() {
    // A pre-normalised scope (no commas) should pass through unchanged
    let claims = make_jwt_bearer_claims(ISS.into(), "openid email".into(), AUD.into(), None, None);
    assert_eq!(claims.scope, "openid email");
}
