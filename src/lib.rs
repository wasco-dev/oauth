wit_bindgen::generate!({
    world: "main",
    path: "wit",
    generate_all,
});

mod sign;

#[cfg(test)]
mod tests;

use exports::wasco_dev::oauth::jwt_client::Guest;
use wasco_dev::oauth::types::{ClientAssertionClaims, JwtBearerClaims, SignResult};

struct Component;

export!(Component);

impl Guest for Component {
    fn make_jwt_bearer_claims(
        issuer: String,
        scope: String,
        audience: String,
        expiry_seconds: Option<u32>,
        subject: Option<String>,
    ) -> JwtBearerClaims {
        sign::make_jwt_bearer_claims(issuer, scope, audience, expiry_seconds, subject)
    }

    fn make_client_assertion_claims(
        client_id: String,
        audience: String,
        expiry_seconds: Option<u32>,
    ) -> ClientAssertionClaims {
        sign::make_client_assertion_claims(client_id, audience, expiry_seconds)
    }

    fn sign(private_key_pem: String, claims: JwtBearerClaims) -> SignResult {
        sign::sign(&private_key_pem, claims)
    }

    fn sign_client_assertion(private_key_pem: String, claims: ClientAssertionClaims) -> SignResult {
        sign::sign_client_assertion(&private_key_pem, claims)
    }
}