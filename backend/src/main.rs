mod audit;
mod backup;
mod cli;
mod commands;
mod config;
mod console;
mod error;
mod keys;
mod password;
mod ratelimit;
mod recovery;
mod router;
mod routes;
mod session;
mod state;
mod validation;

use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = cli::parse(&args).unwrap_or_else(|usage| {
        eprintln!("{usage}");
        std::process::exit(2);
    });

    // Without RUST_LOG, fmt::init() only shows errors: warnings would be invisible. Default to
    // info for the server, warnings only for the console (its screen stays readable).
    let default_level = if matches!(command, cli::Command::Console) {
        "warn"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();
    dotenvy::dotenv().ok();
    if let cli::Command::Help = command {
        println!("{}", cli::USAGE);
        return;
    }
    // Needs neither the database nor the keys
    if let cli::Command::UpdateCheck = command {
        if let Err(e) = commands::update_check().await {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }

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

    let result = match command {
        cli::Command::Recover(file) => commands::recover(&db, &config, &file).await,
        cli::Command::RotateKey(file) => commands::rotate_key(&db, &config, &file).await,
        cli::Command::NewRecoveryKey => commands::new_recovery_key(&db, &config).await,
        cli::Command::Backup => commands::backup(&db, &config).await,
        cli::Command::BackupVerify => commands::backup_verify(&config),
        cli::Command::Restore(file, key_file) => {
            commands::restore(&db, &config, std::path::Path::new(&file), &key_file).await
        }
        cli::Command::Console => {
            console::run(&db, &config).await;
            Ok(())
        }
        cli::Command::Serve | cli::Command::Help | cli::Command::UpdateCheck => {
            serve(db, config).await
        }
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn serve(db: sqlx::PgPool, config: config::Config) -> Result<(), String> {
    keys::check_org_keys(&db, &config.master_key).await?;
    // Kept until the server stops: tells the host commands that Cléa is running
    let _server_lock = commands::hold_server_lock(&db).await;

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

    // Background task: scheduled backups and deletion of expired ones
    if let Some(dir) = config.backup_dir.clone() {
        let db_backup = db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(900));
            loop {
                interval.tick().await;
                backup::scheduled(&db_backup, &dir).await;
            }
        });
    }

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
    Ok(())
}
