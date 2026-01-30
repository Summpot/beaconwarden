use serde::{Deserialize, Serialize};
use serde_json::Value;

use entity::user;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalDomain {
    #[serde(rename = "type")]
    r#type: i32,
    domains: Vec<String>,

    #[serde(default)]
    excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../../../src/static/global_domains.json");

fn parse_json_or_default<T: for<'de> Deserialize<'de> + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_default()
}

/// Build the Bitwarden/Vaultwarden-compatible domains response.
///
/// If `no_excluded` is true, excluded global domain entries are omitted.
pub fn domains_json_for_user(u: &user::Model, no_excluded: bool) -> Value {
    let equivalent_domains: Vec<Vec<String>> = parse_json_or_default(&u.equivalent_domains);
    let excluded_globals: Vec<i32> = parse_json_or_default(&u.excluded_globals);

    let mut globals: Vec<GlobalDomain> = serde_json::from_str(GLOBAL_DOMAINS).unwrap_or_default();
    for g in &mut globals {
        g.excluded = excluded_globals.contains(&g.r#type);
    }
    if no_excluded {
        globals.retain(|g| !g.excluded);
    }

    serde_json::json!({
        "equivalentDomains": equivalent_domains,
        "globalEquivalentDomains": globals,
        "object": "domains",
    })
}
