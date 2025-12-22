//! Authorization helper functions for REST API handlers.

use axum::http::StatusCode;
use uuid::Uuid;

use crate::auth::AuthContext;

/// Check if the auth context represents a bootstrap admin (nil tenant, admin perms).
pub fn is_bootstrap_admin(auth: &AuthContext) -> bool {
    auth.is_admin() && auth.tenant_id.is_nil()
}

/// Ensure the caller can access the given tenant/store, considering bootstrap admin.
pub fn ensure_tenant_store(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if is_bootstrap_admin(auth) {
        return Ok(());
    }

    if auth.tenant_id != tenant_id {
        return Err((StatusCode::FORBIDDEN, "Tenant access denied".to_string()));
    }

    if !store_id.is_nil() && !auth.can_access_store(&store_id) {
        return Err((StatusCode::FORBIDDEN, "Store access denied".to_string()));
    }

    Ok(())
}

/// Ensure the caller has read permission and can access the tenant/store.
pub fn ensure_read(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}

/// Ensure the caller has write permission and can access the tenant/store.
pub fn ensure_write(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            "Write permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}

/// Ensure the caller has admin permission and can access the tenant/store.
pub fn ensure_admin(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Admin permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}
