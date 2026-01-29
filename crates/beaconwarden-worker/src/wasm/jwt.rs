use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;

/// Minimal HS256 JWT utilities.
///
/// Notes:
/// - Only supports JSON objects for header/payload.
/// - Uses base64url encoding WITHOUT padding.
/// - Performs signature verification using `Hmac::verify_slice`.
///
/// This is intentionally small and wasm-friendly.

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, worker::Error> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| worker::Error::RustError(format!("Invalid base64url: {e}")))
}

/// Encode claims as an HS256-signed JWT.
pub fn encode_hs256<T: Serialize>(secret: &[u8], claims: &T) -> Result<String, worker::Error> {
    let header = JwtHeader {
        alg: "HS256".to_string(),
        typ: "JWT".to_string(),
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| worker::Error::RustError(format!("Failed to serialize JWT header: {e}")))?;
    let claims_json = serde_json::to_vec(claims)
        .map_err(|e| worker::Error::RustError(format!("Failed to serialize JWT claims: {e}")))?;

    let header_b64 = b64url_encode(&header_json);
    let claims_b64 = b64url_encode(&claims_json);
    let signing_input = format!("{header_b64}.{claims_b64}");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|e| worker::Error::RustError(format!("Invalid HMAC key: {e}")))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_b64 = b64url_encode(&signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decode an HS256 JWT and verify signature.
///
/// This does not validate `iss`, `exp`, or `nbf`; callers must do that.
pub fn decode_hs256<T: DeserializeOwned>(secret: &[u8], token: &str) -> Result<T, worker::Error> {
    let token = token.replace(char::is_whitespace, "");
    let mut parts = token.split('.');
    let Some(header_b64) = parts.next() else {
        return Err(worker::Error::RustError("Invalid JWT format".to_string()));
    };
    let Some(payload_b64) = parts.next() else {
        return Err(worker::Error::RustError("Invalid JWT format".to_string()));
    };
    let Some(sig_b64) = parts.next() else {
        return Err(worker::Error::RustError("Invalid JWT format".to_string()));
    };
    if parts.next().is_some() {
        return Err(worker::Error::RustError("Invalid JWT format".to_string()));
    }

    // Parse header (best-effort) to ensure alg/typ are what we expect.
    let header_raw = b64url_decode(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_raw)
        .map_err(|e| worker::Error::RustError(format!("Invalid JWT header JSON: {e}")))?;
    if header.alg != "HS256" || header.typ.to_ascii_uppercase() != "JWT" {
        return Err(worker::Error::RustError("Unsupported JWT header".to_string()));
    }

    // Verify signature.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = b64url_decode(sig_b64)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|e| worker::Error::RustError(format!("Invalid HMAC key: {e}")))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| worker::Error::RustError("Invalid JWT signature".to_string()))?;

    // Parse payload.
    let payload_raw = b64url_decode(payload_b64)?;
    let claims: T = serde_json::from_slice(&payload_raw)
        .map_err(|e| worker::Error::RustError(format!("Invalid JWT payload JSON: {e}")))?;

    Ok(claims)
}
