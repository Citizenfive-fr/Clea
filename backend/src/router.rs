use axum::{
    extract::{Request, State},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use tower_http::services::{ServeDir, ServeFile};

use crate::routes;
use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::app::index_page))
        .route("/app", get(routes::app::page))
        .route("/team", get(routes::app::team_page))
        .route("/profile", get(routes::app::profile_page))
        .route("/invite", get(routes::app::invite_page))
        .route("/documentation", get(routes::app::documentation_page))
        .route(
            "/documentation/champ-application",
            get(routes::app::doc_champ_application_page),
        )
        .route(
            "/documentation/principes-fondamentaux",
            get(routes::app::doc_principes_fondamentaux_page),
        )
        .route(
            "/documentation/bases-legales",
            get(routes::app::doc_bases_legales_page),
        )
        .route("/actualites", get(routes::app::actualites_page))
        .route("/setup", get(routes::setup::page))
        .route("/login", get(routes::auth::login_page))
        .nest("/api", routes::api_router())
        // Static assets use an allowlist: html/ must never be served directly,
        // otherwise the session checks done in routes/app.rs could be bypassed
        .nest_service("/css", ServeDir::new("../frontend/css"))
        .nest_service("/js", ServeDir::new("../frontend/js"))
        .route_service("/icon.svg", ServeFile::new("../frontend/icon.svg"))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

/// Headers added to every response. The Content-Security-Policy is set per page
/// in routes::app::html_page because it carries a per-request nonce.
async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api");
    let mut res = next.run(req).await;
    let h = res.headers_mut();

    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    if state.config.secure_cookies {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    // API answers carry account data: never cache them
    if is_api {
        h.entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    }
    res
}
