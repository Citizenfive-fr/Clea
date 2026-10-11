use sqlx::PgPool;
use uuid::Uuid;

pub async fn log(
    db: &PgPool,
    org_id: Option<Uuid>,
    user_id: Option<Uuid>,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (id, organization_id, user_id, action, resource_type, resource_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(user_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .execute(db)
    .await
    {
        // Never block the main flow, but do not fail silently either
        tracing::warn!("Écriture du journal d'audit échouée : {}", e);
    }
}
