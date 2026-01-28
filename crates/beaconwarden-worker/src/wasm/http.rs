use std::fmt::Display;

use worker::{Headers, Request, Response, Result};

fn cors_headers(req: &Request) -> Result<Headers> {
    let headers = Headers::new();

    // Reflect Origin when present; otherwise allow all.
    // Bitwarden clients typically do not rely on CORS, but web vault / browser extensions do.
    let origin = req.headers().get("Origin")?.unwrap_or_else(|| "*".to_string());

    headers.set("Access-Control-Allow-Origin", &origin)?;
    headers.set("Vary", "Origin")?;
    headers.set("Access-Control-Allow-Credentials", "true")?;
    headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Authorization,Content-Type,Accept,X-Requested-With",
    )?;

    Ok(headers)
}

pub fn json_with_cors(req: &Request, mut resp: Response) -> Result<Response> {
    let headers = cors_headers(req)?;
    let resp_headers = resp.headers_mut();
    for (k, v) in headers.entries() {
        resp_headers.set(&k, &v)?;
    }

    Ok(resp)
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
