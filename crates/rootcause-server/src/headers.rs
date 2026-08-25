//! Response headers that make the embedded console hard to weaponise.
//!
//! The console ships with the server, so its policy can be strict without
//! breaking anybody's integration: no inline script, no external origin, no
//! framing, no referrer. A console that cannot load a remote script cannot be
//! turned into a delivery vehicle for one.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, header},
    middleware::Next,
    response::Response,
};

/// Content Security Policy applied to every response.
///
/// `script-src 'self'` with no `unsafe-inline` is the reason the console builds
/// its DOM from JavaScript instead of from templated HTML.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
connect-src 'self'; \
img-src 'self' data:; \
style-src 'self'; \
script-src 'self'; \
font-src 'self'; \
base-uri 'none'; \
form-action 'none'; \
frame-ancestors 'none'; \
object-src 'none'";

/// Static headers sent with every response.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("x-permitted-cross-domain-policies", "none"),
];

/// Sent only when the request demonstrably arrived over TLS.
const STRICT_TRANSPORT_SECURITY: &str = "max-age=31536000; includeSubDomains";

fn arrived_over_tls(request: &Request) -> bool {
    request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

pub async fn apply(request: Request, next: Next) -> Response {
    let over_tls = arrived_over_tls(&request);
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    for (name, value) in SECURITY_HEADERS {
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value))
        {
            headers.insert(name, value);
        }
    }
    if over_tls {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(STRICT_TRANSPORT_SECURITY),
        );
    }
    if is_api {
        // Evidence must never be served from a shared cache.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_forbids_inline_script_and_remote_origins() {
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-eval"));
        assert!(!CONTENT_SECURITY_POLICY.contains("http:"));
        assert!(!CONTENT_SECURITY_POLICY.contains('*'));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("object-src 'none'"));
    }

    #[test]
    fn every_declared_header_is_a_valid_header() {
        for (name, value) in SECURITY_HEADERS {
            assert!(HeaderName::from_bytes(name.as_bytes()).is_ok(), "invalid name {name}");
            assert!(HeaderValue::from_str(value).is_ok(), "invalid value for {name}");
        }
    }

    #[test]
    fn the_essential_headers_are_present() {
        let names: Vec<&str> = SECURITY_HEADERS.iter().map(|(name, _)| *name).collect();
        for required in [
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ] {
            assert!(names.contains(&required), "{required} must always be sent");
        }
    }

    #[test]
    fn transport_security_is_only_claimed_for_a_year_over_subdomains() {
        assert!(STRICT_TRANSPORT_SECURITY.contains("max-age=31536000"));
        assert!(STRICT_TRANSPORT_SECURITY.contains("includeSubDomains"));
    }
}
