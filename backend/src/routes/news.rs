use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;

use crate::{error::AppError, session::AuthSession, state::AppState};

#[derive(Serialize)]
pub struct NewsItem {
    pub title: String,
    pub link: String,
    pub pub_date: Option<String>,
    pub source: String,
    pub labels: Vec<String>,
}

#[derive(Serialize)]
pub struct FavoriteItem {
    pub title: String,
    pub link: String,
    pub source: String,
    pub labels: Vec<String>,
    pub added_by: String,
    pub added_at: String,
}

#[derive(Deserialize)]
pub struct AddFavorite {
    pub link: String,
    pub source: String,
    pub title: String,
}

const FEEDS: &[(&str, &str)] = &[
    ("CNIL", "https://www.cnil.fr/fr/rss.xml"),
    ("EDPB", "https://www.edpb.europa.eu/feed/news_en"),
];

const LABEL_RULES: &[(&str, &[&str])] = &[
    (
        "Sanction",
        &["sanction", "amende", "mise en demeure", "penalty", "fine"],
    ),
    (
        "Recommandation",
        &[
            "recommandation",
            "recommendation",
            "guideline",
            "lignes directrices",
        ],
    ),
    ("Fiche pratique", &["fiche pratique", "practical guide"]),
    (
        "Rapport",
        &["rapport annuel", "annual report", "bilan annuel"],
    ),
    ("Délibération", &["délibération", "deliberation"]),
    ("Avis", &["avis rendu", "avis sur", "opinion", "statement"]),
    (
        "Consultation",
        &["consultation publique", "public consultation"],
    ),
];

fn assign_labels(title: &str) -> Vec<String> {
    let lower = title.to_lowercase();
    LABEL_RULES
        .iter()
        .filter(|(_, keywords)| keywords.iter().any(|kw| lower.contains(kw)))
        .map(|(label, _)| label.to_string())
        .collect()
}

pub async fn feeds(
    _session: AuthSession,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<NewsItem>>, AppError> {
    let source_filter = params.get("source").map(|s| s.as_str());
    let limit = if source_filter.is_some() { 25 } else { 10 };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Clea/0.1 RGPD compliance tool")
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut items: Vec<NewsItem> = Vec::new();

    for (source, url) in FEEDS {
        if let Some(filter) = source_filter {
            if *source != filter {
                continue;
            }
        }
        if let Ok(mut feed_items) = fetch_feed(&client, source, url, limit).await {
            items.append(&mut feed_items);
        }
    }

    items.sort_by(|a, b| {
        let parse = |s: &Option<String>| {
            s.as_deref()
                .and_then(|d| DateTime::parse_from_rfc2822(d).ok())
        };
        parse(&b.pub_date).cmp(&parse(&a.pub_date))
    });

    Ok(Json(items))
}

pub async fn list_favorites(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Vec<FavoriteItem>>, AppError> {
    let rows = sqlx::query(
        "SELECT f.link, f.source, f.title, f.created_at::text AS added_at,
                COALESCE(u.username, split_part(u.email, '@', 1)) AS added_by
         FROM news_favorites f
         JOIN users u ON u.id = f.added_by
         WHERE f.organization_id = $1
         ORDER BY f.created_at DESC",
    )
    .bind(session.org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.iter()
            .map(|r| {
                let title: String = r.get("title");
                let labels = assign_labels(&title);
                FavoriteItem {
                    title,
                    link: r.get("link"),
                    source: r.get("source"),
                    labels,
                    added_by: r.get("added_by"),
                    added_at: r.get("added_at"),
                }
            })
            .collect(),
    ))
}

pub async fn add_favorite(
    session: AuthSession,
    State(state): State<AppState>,
    Json(body): Json<AddFavorite>,
) -> Result<StatusCode, AppError> {
    sqlx::query(
        "INSERT INTO news_favorites (organization_id, added_by, link, source, title)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (organization_id, link) DO NOTHING",
    )
    .bind(session.org_id)
    .bind(session.user_id)
    .bind(&body.link)
    .bind(&body.source)
    .bind(&body.title)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_favorite(
    session: AuthSession,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, AppError> {
    let link = params
        .get("link")
        .ok_or_else(|| AppError::BadRequest("Paramètre link manquant".into()))?;

    let row =
        sqlx::query("SELECT added_by FROM news_favorites WHERE organization_id = $1 AND link = $2")
            .bind(session.org_id)
            .bind(link)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Favori introuvable".into()))?;

    let added_by: uuid::Uuid = row.get("added_by");
    if added_by != session.user_id && session.role == "member" {
        return Err(AppError::Unauthorized(
            "Seul l'auteur ou un admin peut retirer ce favori".into(),
        ));
    }

    sqlx::query("DELETE FROM news_favorites WHERE organization_id = $1 AND link = $2")
        .bind(session.org_id)
        .bind(link)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_feed(
    client: &reqwest::Client,
    source: &str,
    url: &str,
    limit: usize,
) -> Result<Vec<NewsItem>, ()> {
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|_| ())?
        .bytes()
        .await
        .map_err(|_| ())?;

    let channel = rss::Channel::read_from(&bytes[..]).map_err(|_| ())?;

    Ok(channel
        .items()
        .iter()
        .take(limit)
        .map(|item| {
            let title = item.title().unwrap_or("Sans titre").to_string();
            let labels = assign_labels(&title);
            NewsItem {
                title,
                link: item.link().unwrap_or("").to_string(),
                pub_date: item.pub_date().map(|d| d.to_string()),
                source: source.to_string(),
                labels,
            }
        })
        .collect())
}
