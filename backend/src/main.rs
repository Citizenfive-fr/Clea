mod audit;
mod cli;
mod config;
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
    // Without RUST_LOG, fmt::init() only shows errors: warnings would be invisible. Default to info.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = cli::parse(&args).unwrap_or_else(|usage| {
        eprintln!("{usage}");
        std::process::exit(2);
    });
    if let cli::Command::Help = command {
        println!("{}", cli::USAGE);
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

    match command {
        cli::Command::Recover(file) => {
            match cli::recover(&db, &config.master_key, &file).await {
                Ok(recovered) => {
                    for org in &recovered {
                        println!(
                            "Organisation « {} » : clé récupérée et enfermée avec la nouvelle \
                             clé maîtresse.",
                            org.name
                        );
                        print_new_recovery_key(&org.new_recovery_key);
                    }
                    let shred = if file == "-" {
                        "shred -u <fichier>".to_string()
                    } else {
                        format!("shred -u {file}")
                    };
                    println!(
                        "Supprime maintenant le fichier de l'ancienne clé de secours \
                         ({shred}), puis relance Cléa."
                    );
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            if let Err(e) = keys::check_org_keys(&db, &config.master_key).await {
                eprintln!(
                    "Attention, une autre organisation ne s'ouvre pas avec cette clé maîtresse : {e}\n\
                     Son propriétaire doit lancer clea recover avec sa propre clé de secours."
                );
            }
            return;
        }
        cli::Command::RotateKey(file) => {
            match cli::rotate_key(&db, &config.master_key, &file).await {
                Ok(count) => println!(
                    "Clé maîtresse changée pour {count} organisation(s).\n\
                     L'ancienne clé ne marche plus : mets la nouvelle dans APP_SECRET_KEY \
                     ou APP_KEY_FILE, puis relance Cléa."
                ),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        cli::Command::NewRecoveryKey => {
            match cli::new_recovery_key(&db, &config.master_key).await {
                Ok(renewed) => {
                    for org in &renewed {
                        println!("Organisation « {} » :", org.name);
                        print_new_recovery_key(&org.new_recovery_key);
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        cli::Command::Serve | cli::Command::Help => {}
    }

    if let Err(e) = keys::check_org_keys(&db, &config.master_key).await {
        tracing::error!("{}", e);
        std::process::exit(1);
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

/// Shows a new recovery key once, with what to do with it.
fn print_new_recovery_key(key: &str) {
    println!(
        "\nL'ancienne clé de secours ne marche plus. Voici la nouvelle, affichée une seule \
         fois. Garde-la hors de ce serveur, imprimée et rangée dans un \
         endroit sûr. Ne la transmets à personne :\n\n{key}\n"
    );
}
