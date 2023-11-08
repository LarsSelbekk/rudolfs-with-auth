use std::collections::HashSet;
use std::fmt;

use crate::storage::Namespace;
use base64::Engine;
use http::{header, HeaderMap};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum AuthError {
    Unauthenticated,
    Unauthorized,
    Malformed,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::Unauthenticated => write!(f, "Unauthenticated"),
            AuthError::Unauthorized => write!(f, "Unauthorized"),
            AuthError::Malformed => write!(f, "Malformed auth header"),
        }
    }
}

pub type JwtKeyType = jsonwebtoken::DecodingKey;

pub fn verify_edit_access(
    namespace: &Namespace,
    headers: &HeaderMap,
    private_key: &Option<JwtKeyType>,
) -> Result<(), AuthError> {
    match private_key {
        None => Ok(()),
        Some(private_key) => match headers.get(header::AUTHORIZATION) {
            None => Err(AuthError::Unauthenticated),
            Some(auth) => {
                match auth
                    .to_str()
                    .map_err(|_| AuthError::Malformed)?
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>()[..]
                {
                    ["Basic", blob] => {
                        let decoded = String::from_utf8(
                            base64::engine::GeneralPurpose::new(
                                &base64::alphabet::STANDARD,
                                base64::engine::GeneralPurposeConfig::default(),
                            )
                            .decode(blob)
                            .unwrap(),
                        )
                        .unwrap();

                        if let Some(token) = decoded.split(':').nth(1) {
                            if verify_token(token, namespace, private_key) {
                                Ok(())
                            } else {
                                Err(AuthError::Unauthorized)
                            }
                        } else {
                            Err(AuthError::Malformed)
                        }
                    }
                    _ => Err(AuthError::Malformed),
                }
            }
        },
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenPayload {
    namespaces: Vec<String>,
}

pub fn verify_token(
    token: &str,
    namespace: &Namespace,
    private_key: &JwtKeyType,
) -> bool {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::new();

    let result =
        jsonwebtoken::decode::<TokenPayload>(token, private_key, &validation);

    if result.is_err() {
        return false;
    };

    result.unwrap().claims.namespaces.iter().any(|grant| {
        namespace.to_string() == *grant
            || (!grant.contains('/') && namespace.org() == *grant)
    })
}

pub fn parse_private_key(private_key: String) -> JwtKeyType {
    JwtKeyType::from_secret(private_key.as_bytes())
}
