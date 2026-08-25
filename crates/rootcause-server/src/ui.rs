use axum::{
    body::Body,
    extract::Uri,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../console/"]
struct ConsoleAssets;

pub async fn static_asset(uri: Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    if requested.starts_with("api/") || requested == "healthz" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if requested.is_empty() { "index.html" } else { requested };

    let asset = ConsoleAssets::get(path)
        .map(|content| (path, content))
        .or_else(|| ConsoleAssets::get("index.html").map(|content| ("index.html", content)));
    match asset {
        Some((asset_path, content)) => {
            let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, "no-cache"),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (header::X_FRAME_OPTIONS, "DENY"),
                ],
                Body::from(content.data.into_owned()),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
