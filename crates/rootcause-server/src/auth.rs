use axum::{
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

use crate::{error::ApiError, state::AppState};

pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(expected) = state.api_token.as_deref() else {
        return Ok(next.run(request).await);
    };

    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();

    if supplied.len() != expected.len()
        || !bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
    {
        return Err(ApiError::unauthorized());
    }

    Ok(next.run(request).await)
}
