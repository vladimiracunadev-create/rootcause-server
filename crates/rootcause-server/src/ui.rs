//! The console is compiled into the binary.
//!
//! There is no asset directory to misconfigure, no path traversal to defend
//! against and no CDN in the trust chain: what ships is what is served.

use axum::{
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../console/"]
struct ConsoleAssets;

/// Paths that belong to the API and must never fall through to the console.
fn is_reserved(path: &str) -> bool {
    path.starts_with("api/") || path == "healthz" || path == "readyz" || path == "metrics"
}

pub async fn static_asset(uri: Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    if is_reserved(requested) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if requested.is_empty() { "index.html" } else { requested };

    // Unknown paths render the console shell so client-side navigation works.
    let asset = ConsoleAssets::get(path)
        .map(|content| (path, content))
        .or_else(|| ConsoleAssets::get("index.html").map(|content| ("index.html", content)));

    match asset {
        Some((asset_path, content)) => {
            let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref()), (header::CACHE_CONTROL, "no-cache")],
                Body::from(content.data.into_owned()),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_is_embedded_in_the_binary() {
        for asset in ["index.html", "app.js", "styles.css", "rootcause.svg"] {
            assert!(ConsoleAssets::get(asset).is_some(), "{asset} must ship inside the binary");
        }
    }

    #[test]
    fn api_paths_never_fall_through_to_the_console() {
        assert!(is_reserved("api/v1/status"));
        assert!(is_reserved("healthz"));
        assert!(is_reserved("readyz"));
        assert!(is_reserved("metrics"));
        assert!(!is_reserved("index.html"));
        assert!(!is_reserved(""));
    }

    #[tokio::test]
    async fn an_unknown_path_serves_the_console_shell() {
        let response = static_asset("/incidentes".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_api_path_is_not_served_by_the_console() {
        let response = static_asset("/api/v1/status".parse().unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
