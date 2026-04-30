//! JWT helpers for configuratin, signing, verifying, and extractor claims
//!
//! `init(JWTConfig)` must be called to initialize the key for this module
//!

use anyhow::anyhow;
use hmac::{digest::KeyInit, Hmac};
use jwt::VerifyWithKey;
use jwt::{AlgorithmType, Header, SignWithKey, Token};
use redacted::FullyRedacted;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use once_cell::sync::OnceCell;
static KEY: OnceCell<Hmac<Sha256>> = OnceCell::new();

/// Configuration struct that can be included in your service configuration
#[derive(Clone, Debug, Deserialize)]
pub struct JWTConfig {
    pub key: FullyRedacted<String>,
}

#[derive(Error, Debug)]
pub enum JWTError {
    #[error("The JWT key was not set")]
    KeyNotSet(),
    #[error("Error while trying to sign or verify using JWT lib")]
    SignOrVerifyError( #[from] jwt::Error)
}

/// Initializae the Key for this module
pub fn init(jwt_config: JWTConfig) {
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_config.key.into_inner().as_bytes())
        .expect("JWT Key cannot be set");
    KEY.set(key).ok();
}

/// Sign a serde::Serialize able structure into a String token
pub fn sign(data: impl serde::Serialize) -> Result<String, JWTError> {
    let k = KEY.get().ok_or(JWTError::KeyNotSet())?;
    Ok(data.sign_with_key(k)?)
}

/// Verify a String Token and return a serde::Deserialize d structure
pub fn verify<T>(token: &str) -> Result<T, JWTError>
where
    T: serde::de::DeserializeOwned,
{
    let k = KEY.get().ok_or(JWTError::KeyNotSet())?;
    let claims = token.verify_with_key(k)?;
    Ok(claims)
}

// Extractor / processing
//
use axum_core::extract::FromRequestParts;
use http::request::Parts;
use http::status::StatusCode;

#[derive(Debug)]
pub struct JWTClaims<T>(pub T);

impl<S, T> FromRequestParts<S> for JWTClaims<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Pull the Authorization header
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Missing Authorization header".to_string(),
                )
            })?;

        // Expect "Bearer <token>"
        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization format".to_string(),
            )
        })?;

        let claims: T = crate::jwt::verify(token)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {e}")))?;

        Ok(JWTClaims(claims))
    }
}

pub trait ClaimsGuard: serde::de::DeserializeOwned {
    /// Return Err with a message if this principal isn't authorized.
    fn authorize(&self) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedJWT<T: ClaimsGuard>(pub T);

impl<S, T> FromRequestParts<S> for GuardedJWT<T>
where
    S: Send + Sync,
    T: ClaimsGuard,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let JWTClaims::<T>(claims) = JWTClaims::from_request_parts(parts, state).await?;

        claims
            .authorize()
            .map_err(|msg| (StatusCode::FORBIDDEN, msg))?;

        Ok(GuardedJWT(claims))
    }
}
#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ExampleStruct{
    role: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_sign_and_verify() {
        let cfg = JWTConfig {
            key: FullyRedacted::new("TEST_KEY".to_string()),
        };
        init(cfg);
        let data = ExampleStruct{role: "test_role".to_string()};

        let token = sign(&data).expect("Should work");
        println!("Token: {token}");
        let decoded_data: ExampleStruct = verify(&token).expect("Should work");
        assert_eq!(data, decoded_data);
    }

    #[test]
    fn init_sign_and_verify_with_invalid_data() -> Result<(), String> {
        let cfg = JWTConfig {
            key: FullyRedacted::new("TEST_KEY".to_string()),
        };
        init(cfg);

        // Data from init_sign_and_verify test modifed to be invalid
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidGVzdF9yb2xlIn0.eQ0N-5WhzDvfUABsYou3b82iIO9Oy5NWxIahY311111INVALID";
        let decoded_data: Result<ExampleStruct, JWTError> = verify(&token);

        match decoded_data {
            Err(JWTError::SignOrVerifyError(_)) => Ok(()),
            e => Err(String::from(format!("{e:?} Should have thrown a SignOrVerifyError error")))

        }
    }
}
