mod client_assertion;
mod jwt_bearer;

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

pub const ISS: &str = "test-issuer@example.com";
pub const SCOPE: &str = "openid email profile";
pub const AUD: &str = "https://example.com/token";

/// Returns the current Unix timestamp in seconds (native std::time).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}