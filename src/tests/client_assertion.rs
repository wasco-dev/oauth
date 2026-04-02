use super::{now_secs, AUD};
use crate::sign::make_client_assertion_claims;

const CLIENT_ID: &str = "test-client-id";

// ---------------------------------------------------------------------------
// Timestamp tests
// ---------------------------------------------------------------------------

#[test]
fn iat_is_current_time() {
    let before = now_secs();
    let claims = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), None);
    let after = now_secs();
    assert!(
        claims.iat >= before && claims.iat <= after,
        "iat ({}) not in [{before}, {after}]",
        claims.iat
    );
}

#[test]
fn exp_equals_iat_plus_default_duration() {
    let claims = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), None);
    assert_eq!(
        claims.exp,
        claims.iat + 60,
        "default expiry should be 60 seconds"
    );
}

#[test]
fn exp_equals_iat_plus_custom_duration() {
    let claims = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), Some(120));
    assert_eq!(claims.exp, claims.iat + 120);
}

#[test]
fn explicit_60_matches_default() {
    let default = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), None);
    let explicit = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), Some(60));
    assert_eq!(explicit.exp - explicit.iat, default.exp - default.iat);
}

// ---------------------------------------------------------------------------
// Field assignment tests
// ---------------------------------------------------------------------------

#[test]
fn client_id_assigned_correctly() {
    let claims = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), None);
    assert_eq!(claims.client_id, CLIENT_ID);
}

#[test]
fn audience_assigned_correctly() {
    let claims = make_client_assertion_claims(CLIENT_ID.into(), AUD.into(), None);
    assert_eq!(claims.audience, AUD);
}

#[test]
fn different_audience_url() {
    let custom_aud = "https://custom-idp.example.com/token";
    let claims = make_client_assertion_claims(CLIENT_ID.into(), custom_aud.into(), None);
    assert_eq!(claims.audience, custom_aud);
}
