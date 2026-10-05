mod audit;
mod config;
mod error;
mod router;
mod routes;
mod session;
mod state;

use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let config = config::Config::from_env().unwrap_or_else(|e| {
        tracing::error!("{}", e);
        std::process::exit(1);
    });

    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Connexion PostgreSQL échouée : {}", e);
            std::process::exit(1);
        });

    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Migrations échouées : {}", e);
            std::process::exit(1);
        });

    tracing::info!("Base de données prête");

    // Background task: clean expired sessions every hour
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&db_cleanup)
                .await
            {
                Ok(r) => tracing::debug!("Sessions expirées supprimées : {}", r.rows_affected()),
                Err(e) => tracing::warn!("Erreur nettoyage sessions : {}", e),
            }
        }
    });

    let state = state::AppState::new(db, config);
    let app = router::build(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Cléa écoute sur http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
