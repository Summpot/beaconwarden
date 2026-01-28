use worker::Env;

pub fn normalize_env_value(raw: String) -> String {
    let trimmed = raw.trim();

    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return inner.trim().to_string();
    }
    if let Some(inner) = trimmed.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.trim().to_string();
    }

    trimmed.to_string()
}

pub fn env_string(env: &Env, key: &str) -> Option<String> {
    env.var(key)
        .ok()
        .map(|v| normalize_env_value(v.to_string()))
        .filter(|s| !s.is_empty())
}
