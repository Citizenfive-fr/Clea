pub mod app;
pub mod auth;
pub mod health;
pub mod invitations;
pub mod news;
pub mod setup;
pub mod totp;
pub mod users;

use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/setup/status", get(setup::status))
        .route("/setup", post(setup::complete))
        .route("/auth/me", get(auth::me))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/username", post(auth::update_username))
        .route("/auth/2fa/setup", post(totp::setup))
        .route("/auth/2fa/confirm", post(totp::confirm))
        .route("/auth/2fa/disable", post(totp::disable))
        .route("/auth/2fa/verify", post(totp::verify))
        .route("/users", get(users::list))
        .route("/users/{id}", axum::routing::delete(users::delete))
        .route(
            "/users/{id}/sessions",
            axum::routing::delete(users::logout_sessions),
        )
        .route("/invitations/check", get(invitations::check))
        .route("/invitations", post(invitations::create))
        .route("/invitations/accept", post(invitations::accept))
        .route("/news/feeds", get(news::feeds))
        .route(
            "/news/favorites",
            get(news::list_favorites)
                .post(news::add_favorite)
                .delete(news::remove_favorite),
        )
}
