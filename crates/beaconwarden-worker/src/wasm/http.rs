use std::fmt::Display;

use worker::{Headers, Request, Response, Result};

fn cors_headers(req: &Request) -> Result<Headers> {
    let headers = Headers::new();

    // Reflect Origin when present; otherwise allow all.
    // Bitwarden clients typically do not rely on CORS, but web vault / browser extensions do.
    let origin = req.headers().get("Origin")?;

    match origin.as_deref() {
        Some(o) if !o.trim().is_empty() => {
            headers.set("Access-Control-Allow-Origin", o)?;
            // Needed when reflecting Origin.
            headers.set("Access-Control-Allow-Credentials", "true")?;
        }
        _ => {
            // Non-browser callers typically omit Origin; allow any.
            headers.set("Access-Control-Allow-Origin", "*")?;
        }
    }

    headers.set(
        "Vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    )?;
    headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Authorization,Content-Type,Accept,X-Requested-With,Device-Type,Device-Identifier,Device-Name,Bitwarden-Client-Name,Bitwarden-Client-Version",
    )?;
    // Cache preflights for a day.
    headers.set("Access-Control-Max-Age", "86400")?;

    Ok(headers)
}

fn security_headers() -> Result<Headers> {
    let headers = Headers::new();

    // Conservative security headers for an API-only service.
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("X-Frame-Options", "DENY")?;
    headers.set("Referrer-Policy", "no-referrer")?;

    // Avoid caching API responses (important for auth and sync).
    headers.set("Cache-Control", "no-store")?;
    headers.set("Pragma", "no-cache")?;

    Ok(headers)
}

fn apply_headers(req: &Request, mut resp: Response) -> Result<Response> {
    let cors = cors_headers(req)?;
    let sec = security_headers()?;
    let resp_headers = resp.headers_mut();

    for (k, v) in cors.entries() {
        resp_headers.set(&k, &v)?;
    }
    for (k, v) in sec.entries() {
        resp_headers.set(&k, &v)?;
    }

    Ok(resp)
}

pub fn json_with_cors(req: &Request, resp: Response) -> Result<Response> {
    // Backwards-compat name; now applies both CORS and common security headers.
    apply_headers(req, resp)
}

pub fn error_response(req: &Request, status: u16, code: &str, message: &str) -> Result<Response> {
    let body = serde_json::json!({
        "success": false,
        "error": {
            "code": code,
            "message": message
        }
    });

    let resp = Response::from_json(&body)?.with_status(status as u16);
    json_with_cors(req, resp)
}

pub fn internal_error_response<E: Display>(req: &Request, context: &str, err: &E) -> Result<Response> {
    worker::console_log!("{context}: {err}");
    error_response(req, 500, "internal_error", "Internal server error")
}

pub fn not_found(req: &Request) -> Result<Response> {
    error_response(req, 404, "not_found", "Not found")
}
