use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
};
use sqlx::Row;

use crate::{
    session::{extract_session_token, hash_token},
    state::AppState,
};

const NO_STORE: &str = "no-store";

pub async fn page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return Redirect::to("/login").into_response();
    }
    no_cache(Html(
        tokio::fs::read_to_string("../frontend/html/app.html")
            .await
            .unwrap_or_default(),
    ))
}

pub async fn team_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match get_role(&state, &headers).await {
        None => Redirect::to("/login").into_response(),
        Some(role) if role == "member" => Redirect::to("/app").into_response(),
        _ => no_cache(Html(
            tokio::fs::read_to_string("../frontend/html/team.html")
                .await
                .unwrap_or_default(),
        )),
    }
}

pub async fn profile_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return Redirect::to("/login").into_response();
    }
    no_cache(Html(
        tokio::fs::read_to_string("../frontend/html/profile.html")
            .await
            .unwrap_or_default(),
    ))
}

fn no_cache(html: Html<String>) -> Response {
    let mut res = html.into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    res
}

pub async fn index_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/index.html")
            .await
            .unwrap_or_default(),
    )
}

pub async fn invite_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/invite.html")
            .await
            .unwrap_or_default(),
    )
}

pub async fn documentation_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return Redirect::to("/login").into_response();
    }
    no_cache(Html(
        tokio::fs::read_to_string("../frontend/html/documentation.html")
            .await
            .unwrap_or_default(),
    ))
}

pub async fn doc_champ_application_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/doc-champ-application.html")
            .await
            .unwrap_or_default(),
    )
}

pub async fn doc_principes_fondamentaux_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/doc-principes-fondamentaux.html")
            .await
            .unwrap_or_default(),
    )
}

pub async fn doc_bases_legales_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/doc-bases-legales.html")
            .await
            .unwrap_or_default(),
    )
}

pub async fn actualites_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return Redirect::to("/login").into_response();
    }
    no_cache(Html(
        tokio::fs::read_to_string("../frontend/html/actualites.html")
            .await
            .unwrap_or_default(),
    ))
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

async fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    get_role(state, headers).await.is_some()
}
