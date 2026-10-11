mod audit;
mod config;
mod crypto;
mod error;
mod password;
mod ratelimit;
mod router;
mod routes;
mod session;
mod state;
mod validation;

use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Without RUST_LOG, fmt::init() only shows errors: warnings would be invisible. Default to info.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
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

    match crypto::encrypt_legacy_totp_secrets(&db, &config.app_secret_key).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("Secrets 2FA chiffrés : {}", n),
        Err(_) => {
            tracing::error!("Chiffrement des secrets 2FA existants échoué");
            std::process::exit(1);
        }
    }

    tracing::info!("Base de données prête");

    // Background task: clean expired sessions every hour
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = sqlx::query(
                "DELETE FROM invitations WHERE expires_at < now() AND accepted_at IS NULL",
            )
            .execute(&db_cleanup)
            .await
            {
                tracing::warn!("Erreur nettoyage invitations : {}", e);
            }
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

    // Background task: purge expired rate-limit entries and pending 2FA tokens
    let purge_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            purge_state.login_ip_limiter.purge();
            purge_state.login_email_limiter.purge();
            purge_state.totp_user_limiter.purge();
            purge_state.reauth_limiter.purge();
            purge_state
                .pending_2fa
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|_, (_, created, _)| created.elapsed().as_secs() < 300);
        }
    });

    let app = router::build(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Cléa écoute sur http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
