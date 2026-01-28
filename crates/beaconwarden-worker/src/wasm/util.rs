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
