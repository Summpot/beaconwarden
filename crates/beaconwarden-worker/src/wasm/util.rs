use chrono::{TimeZone, Utc};

use getrandom::fill;

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

pub fn ts_to_rfc3339(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
    .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap())
        .to_rfc3339()
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    fill(&mut out).expect("Failed to generate random bytes");
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn generate_access_token() -> String {
    // 256-bit token, hex-encoded.
    hex_encode(&random_bytes(32))
}

pub fn generate_refresh_token() -> String {
    // 256-bit token, hex-encoded.
    hex_encode(&random_bytes(32))
}

pub fn generate_security_stamp() -> String {
    // 128-bit token, hex-encoded.
    hex_encode(&random_bytes(16))
}

pub fn uuid_v4() -> String {
    // Generate a UUIDv4 string without pulling in an additional dependency.
    // Format: 8-4-4-4-12 hex characters.
    let mut b = random_bytes(16);

    // Set version = 4.
    b[6] = (b[6] & 0x0f) | 0x40;
    // Set variant = RFC4122.
    b[8] = (b[8] & 0x3f) | 0x80;

    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);

    for (i, byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }

    out
}
