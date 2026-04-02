use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey};
use sha2::Sha256;

use crate::wasco_dev::oauth::types::{
    ClientAssertionClaims, JwtBearerClaims, SignError, SignResult,
};
// ---------------------------------------------------------------------------
// WASI shims — replaced with native implementations in cfg(test)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
fn wasi_now_secs() -> u64 {
    crate::wasi::clocks::wall_clock::now().seconds
}
#[cfg(test)]
fn wasi_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(not(test))]
fn wasi_random_bytes(n: u64) -> Vec<u8> {
    crate::wasi::random::random::get_random_bytes(n)
}
#[cfg(test)]
fn wasi_random_bytes(n: u64) -> Vec<u8> {
    // Deterministic sequence — sufficient for RSA blinding and JTI in tests
    (0..n as u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(13))
        .collect()
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn err(msg: impl Into<String>) -> SignError {
    SignError {
        message: msg.into(),
    }
}

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

fn b64url(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

fn b64url_str(s: &str) -> String {
    b64url(s.as_bytes())
}

// ---------------------------------------------------------------------------
// jti generation
// ---------------------------------------------------------------------------

// 16 random bytes → 22-character base64url string.
// Satisfies the uniqueness requirement of RFC 7523 §3 and the recommendation
// of §2 without exposing jti as a caller-supplied parameter.

fn generate_jti() -> String {
    let bytes = wasi_random_bytes(16);
    b64url(&bytes)
}

// ---------------------------------------------------------------------------
// Shared signing core
// ---------------------------------------------------------------------------

const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

fn signing_key_from_pem(pem: &str) -> Result<SigningKey<Sha256>, SignError> {
    // PEM keys stored in env vars or secrets often have literal \n (two chars)
    // instead of real newlines. Normalise before parsing.
    let normalised;
    let pem = if pem.contains("\\n") {
        normalised = pem.replace("\\n", "\n");
        &normalised
    } else {
        pem
    };
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| err(e.to_string()))?;
    Ok(SigningKey::<Sha256>::new(private_key))
}

fn compact_jwt(signing_key: &SigningKey<Sha256>, payload: &str) -> String {
    let signing_input = format!("{}.{}", b64url_str(HEADER), b64url_str(payload));
    let mut rng = WasiRng;
    let sig = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
    format!("{}.{}", signing_input, b64url(sig.to_bytes().as_ref()))
}

// ---------------------------------------------------------------------------
// Claims constructors — read the wall clock, compute iat/exp
// ---------------------------------------------------------------------------

pub fn make_jwt_bearer_claims(
    issuer: String,
    scope: String,
    audience: String,
    expiry_seconds: Option<u32>,
    subject: Option<String>,
) -> JwtBearerClaims {
    let scope_normalised = scope
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ");
    let iat = wasi_now_secs();
    let exp = iat + expiry_seconds.unwrap_or(3600) as u64;
    JwtBearerClaims {
        issuer,
        scope: scope_normalised,
        audience,
        iat,
        exp,
        subject,
    }
}

pub fn make_client_assertion_claims(
    client_id: String,
    audience: String,
    expiry_seconds: Option<u32>,
) -> ClientAssertionClaims {
    let iat = wasi_now_secs();
    let exp = iat + expiry_seconds.unwrap_or(60) as u64;
    ClientAssertionClaims {
        client_id,
        audience,
        iat,
        exp,
    }
}

// ---------------------------------------------------------------------------
// RFC 7523 §2 — JWT authorization grant
// ---------------------------------------------------------------------------

pub fn sign(pem: &str, claims: JwtBearerClaims) -> SignResult {
    let signing_key = match signing_key_from_pem(pem) {
        Ok(k) => k,
        Err(e) => {
            return SignResult {
                jwt: None,
                jti: None,
                error: Some(e),
            }
        }
    };
    let jti = generate_jti();
    let sub = claims.subject.as_deref().unwrap_or(&claims.issuer);

    let payload = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","scope":"{scope}","aud":"{aud}","iat":{iat},"exp":{exp},"jti":"{jti}"}}"#,
        iss = claims.issuer,
        sub = sub,
        scope = claims.scope,
        aud = claims.audience,
        iat = claims.iat,
        exp = claims.exp,
        jti = jti,
    );

    SignResult {
        jwt: Some(compact_jwt(&signing_key, &payload)),
        jti: Some(jti),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// RFC 7523 §3 — JWT client authentication assertion
// ---------------------------------------------------------------------------

pub fn sign_client_assertion(pem: &str, claims: ClientAssertionClaims) -> SignResult {
    let signing_key = match signing_key_from_pem(pem) {
        Ok(k) => k,
        Err(e) => {
            return SignResult {
                jwt: None,
                jti: None,
                error: Some(e),
            }
        }
    };
    let jti = generate_jti();

    // Per RFC 7523 §3: iss == sub == client_id
    let payload = format!(
        r#"{{"iss":"{cid}","sub":"{cid}","aud":"{aud}","iat":{iat},"exp":{exp},"jti":"{jti}"}}"#,
        cid = claims.client_id,
        aud = claims.audience,
        iat = claims.iat,
        exp = claims.exp,
        jti = jti,
    );

    SignResult {
        jwt: Some(compact_jwt(&signing_key, &payload)),
        jti: Some(jti),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Minimal RNG adapter for RSA blinding
// ---------------------------------------------------------------------------

// The `rsa` crate's PKCS1v15 signer requires `rand_core::CryptoRng +
// rand_core::RngCore` purely for RSA blinding (to prevent timing side-channel
// attacks). The blinding value is ephemeral and does NOT affect the
// deterministic signature. We satisfy the trait by forwarding to the WASI
// `random/random` interface.

struct WasiRng;

use rsa::rand_core::{CryptoRng, Error as RngError, RngCore};

impl CryptoRng for WasiRng {}

impl RngCore for WasiRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = wasi_random_bytes(dest.len() as u64);
        let len = bytes.len().min(dest.len());
        dest[..len].copy_from_slice(&bytes[..len]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
