use std::num::NonZeroU32;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const OUTPUT_LEN: usize = 32;

/// Derive the server-side password hash.
///
/// BeaconWarden follows Vaultwarden's approach: the client sends a derived master password
/// hash (not the raw master password). The server then applies an additional PBKDF2 layer
/// with a random per-user salt and server-configured iterations.
pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN];
    let iterations = NonZeroU32::new(iterations).expect("Iterations must be non-zero");
    pbkdf2_hmac::<Sha256>(secret, salt, iterations.get(), &mut out);
    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], expected: &[u8], iterations: u32) -> bool {
    let iterations = NonZeroU32::new(iterations).expect("Iterations must be non-zero");
    if expected.len() != OUTPUT_LEN {
        return false;
    }

    // Derive and constant-time compare.
    let mut out = vec![0u8; OUTPUT_LEN];
    pbkdf2_hmac::<Sha256>(secret, salt, iterations.get(), &mut out);
    subtle::ConstantTimeEq::ct_eq(out.as_ref(), expected).into()
}
