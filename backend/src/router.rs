use axum::{routing::get, Router};
use tower_http::services::ServeDir;

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
        .with_state(state)
        .fallback_service(ServeDir::new("../frontend"))
}
