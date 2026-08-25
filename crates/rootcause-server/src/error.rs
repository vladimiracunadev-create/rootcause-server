//! API errors that say enough to fix the call and nothing more.
//!
//! An error body never carries a stack trace, a query or a token: the detail
//! goes to the server log, the caller gets a stable machine-readable code.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "falta el token bearer o no es válido".to_owned(),
            retry_after_seconds: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    /// The perimeter rejected the request before any credential was compared.
    pub fn throttled(reason: &'static str, retry_after_seconds: u64) -> Self {
        let (code, message) = if reason == "auth.lockout" {
            (
                "locked_out",
                "esta dirección está bloqueada temporalmente por fallos de autenticación repetidos",
            )
        } else {
            ("rate_limited", "se superó el límite de solicitudes para esta dirección")
        };
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            message: message.to_owned(),
            retry_after_seconds: Some(retry_after_seconds.max(1)),
        }
    }

    /// An unexpected failure. The cause is logged; the caller learns nothing.
    pub fn internal(error: anyhow::Error) -> Self {
        error!(error = ?error, "la solicitud falló dentro del servidor");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "error interno del servidor".to_owned(),
            retry_after_seconds: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = self.retry_after_seconds;
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
                code: self.code,
                retry_after_seconds: retry_after,
            }),
        )
            .into_response();
        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_maps_to_the_status_an_operator_expects() {
        assert_eq!(ApiError::bad_request("x").into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::unauthorized().into_response().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::not_found("x").into_response().status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::throttled("auth.lockout", 5).into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn the_lockout_body_names_its_own_code() {
        let error = ApiError::throttled("auth.lockout", 5);
        assert_eq!(error.code, "locked_out");
        assert_eq!(ApiError::throttled("rate.limit", 5).code, "rate_limited");
    }

    #[test]
    fn a_throttled_response_tells_the_caller_when_to_come_back() {
        let response = ApiError::throttled("rate.limit", 42).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "42");
    }

    #[test]
    fn a_zero_retry_hint_is_never_sent() {
        let response = ApiError::throttled("rate.limit", 0).into_response();
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn an_internal_error_never_leaks_the_cause() {
        let error = ApiError::internal(anyhow::anyhow!("connection string user=admin password=x"));
        assert!(!format!("{error:?}").contains("password"));
        assert_eq!(error.into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
