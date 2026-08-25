//! Perimeter and credential checks for every protected route.
//!
//! The order matters and is the point of this module: rate limit first, lockout
//! second, credential third. A token comparison that happens before the
//! perimeter is a free oracle for whoever is guessing.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{error::ApiError, state::AppState};

/// Address used when the connection carries no peer information.
const UNKNOWN_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Resolve the client address, honouring `X-Forwarded-For` only when the
/// operator declared that a reverse proxy is in front.
pub fn client_address(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_forwarded_for: bool,
) -> IpAddr {
    if trust_forwarded_for
        && let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        // The left-most entry is the original client; the rest are proxies.
        && let Some(first) = value.split(',').next()
        && let Ok(address) = first.trim().parse::<IpAddr>()
    {
        return address;
    }
    peer.map_or(UNKNOWN_CLIENT, |socket| socket.ip())
}

/// Extract the bearer token supplied by the caller, if any.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Compare two secrets without leaking their difference through timing.
fn tokens_match(supplied: &str, expected: &str) -> bool {
    supplied.len() == expected.len() && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
}

pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Read the peer from the request extensions instead of extracting it: a
    // connection without `ConnectInfo` must still be handled, not rejected.
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let client = client_address(request.headers(), peer, state.trust_forwarded_for);
    let now = std::time::Instant::now();

    let decision = state.perimeter.check(client, now);
    if !decision.is_allowed() {
        state.record_defense(decision.reason(), client, format!("{decision:?}")).await;
        return Err(ApiError::throttled(decision.reason(), decision.retry_after_seconds()));
    }

    let Some(expected) = state.api_token.as_deref() else {
        // Tokenless development mode; the listener is loopback-only by contract.
        return Ok(next.run(request).await);
    };

    let supplied = bearer_token(request.headers()).unwrap_or_default();
    if !tokens_match(supplied, expected) {
        if state.perimeter.record_failure(client, now) {
            warn!(%client, "dirección bloqueada tras repetidos fallos de autenticación");
            state
                .record_defense(
                    "auth.lockout",
                    client,
                    "se alcanzó el umbral de fallos de autenticación".to_owned(),
                )
                .await;
        }
        state.record_defense("auth.rejected", client, String::new()).await;
        return Err(ApiError::unauthorized());
    }

    state.perimeter.record_success(client);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(forwarded: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = forwarded {
            headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn peer() -> Option<SocketAddr> {
        Some("198.51.100.20:44321".parse().unwrap())
    }

    #[test]
    fn the_peer_address_is_used_by_default() {
        let address = client_address(&headers(Some("203.0.113.9")), peer(), false);
        assert_eq!(address.to_string(), "198.51.100.20");
    }

    #[test]
    fn a_trusted_proxy_header_wins_and_only_its_first_entry() {
        let address =
            client_address(&headers(Some("203.0.113.9, 10.0.0.1, 10.0.0.2")), peer(), true);
        assert_eq!(address.to_string(), "203.0.113.9");
    }

    #[test]
    fn a_malformed_forwarded_header_falls_back_to_the_peer() {
        let address = client_address(&headers(Some("no-soy-una-ip")), peer(), true);
        assert_eq!(address.to_string(), "198.51.100.20");
    }

    #[test]
    fn a_connection_without_peer_information_gets_a_stable_placeholder() {
        assert_eq!(client_address(&headers(None), None, false), UNKNOWN_CLIENT);
    }

    #[test]
    fn only_bearer_tokens_are_read() {
        let mut map = HeaderMap::new();
        map.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer abc123"));
        assert_eq!(bearer_token(&map), Some("abc123"));

        map.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc123"));
        assert_eq!(bearer_token(&map), None);

        map.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer_token(&map), None);
    }

    #[test]
    fn token_comparison_rejects_prefixes_and_accepts_the_exact_secret() {
        let expected = "a".repeat(32);
        assert!(tokens_match(&expected, &expected));
        assert!(!tokens_match("a", &expected));
        assert!(!tokens_match(&format!("{expected}extra"), &expected));
        assert!(!tokens_match(&"b".repeat(32), &expected));
    }
}
