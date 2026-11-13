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
    render_page(file, private, &[]).await
}

/// Same as `html_page`, plus `{{KEY}}` placeholders replaced by fixed server-side values
/// (never user input: they are not escaped).
async fn render_page(file: &str, private: bool, vars: &[(&str, &str)]) -> Response {
    let mut html = match tokio::fs::read_to_string(format!("../frontend/html/{file}")).await {
        Ok(html) => html,
        Err(e) => {
            tracing::error!("Page {file} illisible : {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if html.contains(SIDEBAR_MARKER) {
        html = match include_sidebar(&html).await {
            Some(html) => html,
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    }
    for (key, value) in vars {
        html = html.replace(key, value);
    }

    let nonce = random_token();
    let html = html
        .replace("<script", &format!("<script nonce=\"{nonce}\""))
        .replace("<style", &format!("<style nonce=\"{nonce}\""))
        .replace("{{CLEA_VERSION}}", env!("CARGO_PKG_VERSION"));

    // style-src-attr keeps inline style="..." attributes working: they cannot run code.
    let csp = format!(
        "default-src 'self'; \
         script-src 'nonce-{nonce}'; \
         style-src 'self' 'nonce-{nonce}'; \
         style-src-elem 'self' 'nonce-{nonce}'; \
         style-src-attr 'unsafe-inline'; \
         font-src 'self'; \
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

/// `{{SIDEBAR:/path}}` in a page is replaced by partials/sidebar.html, with the link
/// to `/path` marked as the current page.
const SIDEBAR_MARKER: &str = "{{SIDEBAR:";

async fn include_sidebar(html: &str) -> Option<String> {
    let start = html.find(SIDEBAR_MARKER)?;
    let path_start = start + SIDEBAR_MARKER.len();
    let path_len = html[path_start..].find("}}")?;
    let current = &html[path_start..path_start + path_len];

    let sidebar = match tokio::fs::read_to_string("../frontend/html/partials/sidebar.html").await {
        Ok(sidebar) => sidebar,
        Err(e) => {
            tracing::error!("Barre latérale illisible : {e}");
            return None;
        }
    };
    let link = format!("href=\"{current}\" class=\"side__link\"");
    let sidebar = sidebar.replace(&link, &format!("{link} aria-current=\"page\""));

    let mut out = String::with_capacity(html.len() + sidebar.len());
    out.push_str(&html[..start]);
    out.push_str(&sidebar);
    out.push_str(&html[path_start + path_len + 2..]);
    Some(out)
}

const HOME_NAV_SIGNED_IN: &str = r#"<nav class="home__nav" aria-label="Mon compte"><a href="/profile"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>Mon profil</a></nav>"#;

/// Entry page of the instance: first launch goes to /setup. The main button leads to /app
/// for a signed-in user, to /login otherwise.
pub async fn index_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let setup_done =
        sqlx::query_scalar::<_, bool>("SELECT completed FROM setup_state WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .unwrap_or(true);
    if !setup_done {
        return Redirect::to("/setup").into_response();
    }
    let cta = if get_role(&state, &headers).await.is_some() {
        [
            ("{{CTA_HREF}}", "/app"),
            ("{{CTA_LABEL}}", "Ouvrir l'app"),
            ("{{HOME_NAV}}", HOME_NAV_SIGNED_IN),
        ]
    } else {
        [
            ("{{CTA_HREF}}", "/login"),
            ("{{CTA_LABEL}}", "Se connecter"),
            ("{{HOME_NAV}}", ""),
        ]
    };
    // The button depends on the session: never cache this page
    render_page("index.html", true, &cta).await
}

pub async fn invite_page() -> Response {
    html_page("invite.html", false).await
}

pub async fn doc_champ_application_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    private_page(&state, &headers, "doc-champ-application.html").await
}

pub async fn doc_principes_fondamentaux_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    private_page(&state, &headers, "doc-principes-fondamentaux.html").await
}

pub async fn doc_bases_legales_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    private_page(&state, &headers, "doc-bases-legales.html").await
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
        _ => render_page("team.html", true, &[("{{TEAM_HIDDEN}}", "")]).await,
    }
}

async fn private_page(state: &AppState, headers: &HeaderMap, file: &str) -> Response {
    let Some(role) = get_role(state, headers).await else {
        return Redirect::to("/login").into_response();
    };
    // Members cannot manage the team: its sidebar link stays hidden for them
    let team_hidden = if role == "member" { " hidden" } else { "" };
    render_page(file, true, &[("{{TEAM_HIDDEN}}", team_hidden)]).await
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
