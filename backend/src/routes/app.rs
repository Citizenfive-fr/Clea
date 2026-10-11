use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use sqlx::Row;

use crate::{
    session::{extract_session_token, hash_token, random_token},
    state::AppState,
};

/// Reads a page from frontend/html, adds a fresh nonce to its inline <script> and <style>
/// tags and sets a strict Content-Security-Policy that only accepts that nonce.
/// `private` pages (behind a session) are never cached.
pub async fn html_page(file: &str, private: bool) -> Response {
    let html = match tokio::fs::read_to_string(format!("../frontend/html/{file}")).await {
        Ok(html) => html,
        Err(e) => {
            tracing::error!("Page {file} illisible : {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let nonce = random_token();
    let html = html
        .replace("<script", &format!("<script nonce=\"{nonce}\""))
        .replace("<style", &format!("<style nonce=\"{nonce}\""));

    // style-src-attr keeps inline style="..." attributes working: they cannot run code.
    // Google Fonts is still allowed until the font is self-hosted.
    let csp = format!(
        "default-src 'self'; \
         script-src 'nonce-{nonce}'; \
         style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; \
         style-src-elem 'self' 'nonce-{nonce}' https://fonts.googleapis.com; \
         style-src-attr 'unsafe-inline'; \
         font-src https://fonts.gstatic.com; \
         img-src 'self' data:; \
         connect-src 'self'; \
         object-src 'none'; \
         base-uri 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'"
    );

    let mut res = Html(html).into_response();
    let headers = res.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&csp) {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    if private {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

pub async fn index_page() -> Response {
    html_page("index.html", false).await
}

pub async fn invite_page() -> Response {
    html_page("invite.html", false).await
}

pub async fn doc_champ_application_page() -> Response {
    html_page("doc-champ-application.html", false).await
}

pub async fn doc_principes_fondamentaux_page() -> Response {
    html_page("doc-principes-fondamentaux.html", false).await
}

pub async fn doc_bases_legales_page() -> Response {
    html_page("doc-bases-legales.html", false).await
}

pub async fn page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    private_page(&state, &headers, "app.html").await
}

pub async fn profile_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    private_page(&state, &headers, "profile.html").await
}

pub async fn documentation_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    private_page(&state, &headers, "documentation.html").await
}

pub async fn actualites_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    private_page(&state, &headers, "actualites.html").await
}

pub async fn team_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match get_role(&state, &headers).await {
        None => Redirect::to("/login").into_response(),
        Some(role) if role == "member" => Redirect::to("/app").into_response(),
        _ => html_page("team.html", true).await,
    }
}

async fn private_page(state: &AppState, headers: &HeaderMap, file: &str) -> Response {
    if get_role(state, headers).await.is_none() {
        return Redirect::to("/login").into_response();
    }
    html_page(file, true).await
}

async fn get_role(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = extract_session_token(headers)?;
    let token_hash = hash_token(&token);
    let row = sqlx::query(
        "SELECT u.role FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active = TRUE",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .ok()??;
    Some(row.get("role"))
}
