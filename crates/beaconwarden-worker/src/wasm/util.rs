use chrono::{TimeZone, Utc};

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

pub fn ts_to_rfc3339(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
    .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap())
        .to_rfc3339()
}
