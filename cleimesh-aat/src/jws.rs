//! Compact JWS with EdDSA (Ed25519), the only algorithm this crate accepts,
//! and the OKP JWK that carries the keys (RFC 7515, 7517, 8037).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{deny, Error, Result};

/// The JWS `alg` for Ed25519. Anything else, `none` included, is denied
/// (draft section 8.13).
pub const ALG: &str = "EdDSA";

const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

pub(crate) fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| deny("invalid base64url"))
}

/// A public Ed25519 key as a JWK. Private members (`d`) are refused when
/// parsing: `cnf.jwk` must never carry private key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing)]
    d: Option<serde_json::Value>,
}

impl Jwk {
    pub fn from_key(key: &VerifyingKey) -> Self {
        Jwk { kty: "OKP".into(), crv: "Ed25519".into(), x: b64(key.as_bytes()), d: None }
    }

    /// The Ed25519 key, if this JWK is a public OKP Ed25519 key. This is the
    /// alg/key consistency check: an `EdDSA` signature only verifies against
    /// a key that passes here.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        if self.d.is_some() {
            return Err(deny("jwk carries private key material"));
        }
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(deny("jwk is not an Ed25519 key"));
        }
        let bytes: [u8; 32] = unb64(&self.x)?.try_into().map_err(|_| deny("jwk x is not 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| deny("jwk x is not a valid Ed25519 key"))
    }

    /// The RFC 9278 thumbprint URI (SHA-256 over the RFC 7638 members, in
    /// lexicographic order) that derived tokens use as `iss`.
    pub fn thumbprint_uri(&self) -> String {
        let members = serde_json::json!({"crv": self.crv, "kty": self.kty, "x": self.x});
        let canonical = serde_json_canonicalizer::to_vec(&members).expect("JWK members serialize");
        format!("{}{}", THUMBPRINT_URI_PREFIX, b64(Sha256::digest(canonical)))
    }
}

/// A compact JWS split into its parts. The payload stays encoded until the
/// signature is checked (draft section 7, last paragraphs).
pub(crate) struct Compact<'a> {
    pub signing_input: &'a str,
    pub payload_b64: &'a str,
    signature: Vec<u8>,
    alg: String,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

impl<'a> Compact<'a> {
    pub fn parse(token: &'a str) -> Result<Self> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(deny("not a compact JWS"));
        };
        let header: Header = serde_json::from_slice(&unb64(header)?).map_err(|_| deny("invalid JWS header"))?;
        Ok(Compact {
            signing_input: &token[..token.len() - signature.len() - 1],
            payload_b64: payload,
            signature: unb64(signature)?,
            alg: header.alg,
        })
    }

    /// Checks `alg` and the signature under `key`, then decodes the payload.
    pub fn verify(&self, key: &Jwk) -> Result<Vec<u8>> {
        if self.alg != ALG {
            return Err(deny(format!("JWS alg {:?} is not allowed", self.alg)));
        }
        let key = key.verifying_key()?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| deny("malformed signature"))?;
        key.verify(self.signing_input.as_bytes(), &signature).map_err(|_| deny("bad signature"))?;
        unb64(self.payload_b64)
    }

    /// base64url(SHA-256(JWS Signing Input)): what a child puts in `par_hash`.
    pub fn signing_input_hash(&self) -> String {
        b64(Sha256::digest(self.signing_input.as_bytes()))
    }

    /// The payload without checking the signature. Only for a holder reading
    /// its own parent token when deriving.
    pub fn unverified_payload(&self) -> Result<Vec<u8>> {
        unb64(self.payload_b64)
    }

    /// The `jti` read before the signature is checked, only for the chain's
    /// cycle detection (step 2c). Untrusted.
    pub fn unverified_jti(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Jti {
            jti: String,
        }
        let jti: Jti = serde_json::from_slice(&unb64(self.payload_b64)?).map_err(|_| deny("payload has no string jti"))?;
        Ok(jti.jti)
    }
}

/// Signs `payload` (already serialized) as a compact JWS.
pub(crate) fn sign(key: &SigningKey, payload: &[u8]) -> String {
    let header = b64(br#"{"alg":"EdDSA"}"#);
    let signing_input = format!("{}.{}", header, b64(payload));
    let signature = key.sign(signing_input.as_bytes());
    format!("{}.{}", signing_input, b64(signature.to_bytes()))
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        deny(format!("invalid claims: {}", e))
    }
}
