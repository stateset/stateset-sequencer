//! Health check handlers
//!
//! Provides comprehensive health check endpoints with detailed component status:
//! - Database connectivity and pool health
//! - Circuit breaker states
//! - Component health status
//! - System information

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::AuthContextExt;
use crate::domain::{StoreId, TenantId};
use crate::infra::{PoolHealthStatus, Sequencer};
use crate::server::AppState;

/// Response for the basic health check endpoint
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service name
    pub service: &'static str,
    /// Service version
    pub version: &'static str,
    /// Timestamp of health check
    pub timestamp: String,
}

/// Response for the detailed health check endpoint
#[derive(Debug, Serialize)]
pub struct DetailedHealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service name
    pub service: &'static str,
    /// Service version
    pub version: &'static str,
    /// Timestamp of health check
    pub timestamp: String,
    /// Component health details
    pub components: ComponentsHealth,
    /// System information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemInfo>,
}

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All components healthy
    Healthy,
    /// Some components degraded but operational
    Degraded,
    /// Critical components unhealthy
    Unhealthy,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    pub fn is_unhealthy(&self) -> bool {
        matches!(self, HealthStatus::Unhealthy)
    }
}

/// Health status of individual components
#[derive(Debug, Serialize)]
pub struct ComponentsHealth {
    /// Database health
    pub database: ComponentStatus,
    /// Connection pool health
    pub pool: PoolStatus,
    /// Circuit breakers status
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub circuit_breakers: Vec<CircuitBreakerStatus>,
    /// Anchor service status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_service: Option<ComponentStatus>,
}

/// Individual component status
#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
}

/// Connection pool status
#[derive(Debug, Serialize)]
pub struct PoolStatus {
    /// Pool health status
    pub status: HealthStatus,
    /// Total connections in pool
    pub total_connections: u32,
    /// Active (in-use) connections
    pub active_connections: u32,
    /// Idle connections available
    pub idle_connections: u32,
    /// Maximum pool size
    pub max_connections: u32,
    /// Pool utilization percentage
    pub utilization_percent: f64,
    /// Acquisition latency statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_acquisition_ms: Option<f64>,
}

/// Circuit breaker status
#[derive(Debug, Serialize)]
pub struct CircuitBreakerStatus {
    /// Circuit breaker name
    pub name: String,
    /// Current state
    pub state: String,
    /// Number of successful calls
    pub successes: u64,
    /// Number of failed calls
    pub failures: u64,
    /// Number of rejected calls (circuit open)
    pub rejected: u64,
}

/// System information
#[derive(Debug, Serialize)]
pub struct SystemInfo {
    /// Uptime in seconds (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Rust version
    pub rust_version: &'static str,
}

/// Basic health check endpoint.
///
/// Returns a simple health response without performing deep checks.
/// Use this for Kubernetes liveness probes.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Healthy,
        service: "stateset-sequencer",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Readiness check endpoint.
///
/// Checks database connectivity. Use this for Kubernetes readiness probes.
pub async fn readiness_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check database connectivity by reading head from a known stream
    let start = std::time::Instant::now();
    match state
        .sequencer
        .head(
            &TenantId::from_uuid(uuid::Uuid::nil()),
            &StoreId::from_uuid(uuid::Uuid::nil()),
        )
        .await
    {
        Ok(_) => {
            let response_time = start.elapsed().as_millis() as u64;

            // Get pool stats if available
            let pool_status = if let Some(ref monitor) = state.pool_monitor {
                let stats = monitor.stats().await;
                Some(serde_json::json!({
                    "status": pool_health_to_string(stats.status),
                    "utilization": format!("{:.1}%", stats.utilization() * 100.0),
                    "active": stats.active_connections,
                    "idle": stats.idle_connections,
                }))
            } else {
                None
            };

            Ok(Json(serde_json::json!({
                "status": "ready",
                "database": {
                    "connected": true,
                    "response_time_ms": response_time,
                },
                "pool": pool_status,
            })))
        }
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Database unavailable: {}", e),
        )),
    }
}

/// Detailed health check endpoint.
///
/// Performs comprehensive health checks on all components.
/// Returns detailed status information for observability.
pub async fn detailed_health_check(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<(StatusCode, Json<DetailedHealthResponse>), (StatusCode, Json<serde_json::Value>)> {
    if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Admin permission required",
                "code": "FORBIDDEN"
            })),
        ));
    }

    let timestamp = chrono::Utc::now().to_rfc3339();

    // Check database health
    let db_start = std::time::Instant::now();
    let db_result = state
        .sequencer
        .head(
            &TenantId::from_uuid(uuid::Uuid::nil()),
            &StoreId::from_uuid(uuid::Uuid::nil()),
        )
        .await;
    let db_response_time = db_start.elapsed().as_millis() as u64;

    let database_status = match db_result {
        Ok(_) => ComponentStatus {
            name: "postgresql".to_string(),
            status: if db_response_time < 100 {
                HealthStatus::Healthy
            } else if db_response_time < 500 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unhealthy
            },
            message: None,
            response_time_ms: Some(db_response_time),
        },
        Err(e) => ComponentStatus {
            name: "postgresql".to_string(),
            status: HealthStatus::Unhealthy,
            message: Some(format!("Connection failed: {}", e)),
            response_time_ms: Some(db_response_time),
        },
    };

    // Check pool health
    let pool_status = if let Some(ref monitor) = state.pool_monitor {
        let stats = monitor.stats().await;
        PoolStatus {
            status: pool_health_to_health_status(stats.status),
            total_connections: stats.total_connections,
            active_connections: stats.active_connections,
            idle_connections: stats.idle_connections,
            max_connections: stats.max_connections,
            utilization_percent: stats.utilization() * 100.0,
            avg_acquisition_ms: if stats.avg_acquisition_latency_ms > 0.0 {
                Some(stats.avg_acquisition_latency_ms)
            } else {
                None
            },
        }
    } else {
        // Basic pool status without monitor
        PoolStatus {
            status: if database_status.status.is_healthy() {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            },
            total_connections: 0,
            active_connections: 0,
            idle_connections: 0,
            max_connections: 0,
            utilization_percent: 0.0,
            avg_acquisition_ms: None,
        }
    };

    // Check circuit breakers
    let circuit_breakers = if let Some(ref registry) = state.circuit_breaker_registry {
        let status = registry.status().await;
        if let Some(obj) = status.as_object() {
            obj.iter()
                .map(|(name, value)| {
                    let state_str = value
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let stats = value.get("stats").cloned().unwrap_or_default();

                    CircuitBreakerStatus {
                        name: name.clone(),
                        state: state_str.to_string(),
                        successes: stats.get("successes").and_then(|v| v.as_u64()).unwrap_or(0),
                        failures: stats.get("failures").and_then(|v| v.as_u64()).unwrap_or(0),
                        rejected: stats.get("rejected").and_then(|v| v.as_u64()).unwrap_or(0),
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Check anchor service
    let anchor_status = state.anchor_service.as_ref().map(|_| ComponentStatus {
        name: "anchor_service".to_string(),
        status: HealthStatus::Healthy, // Basic check - service is configured
        message: Some("Configured".to_string()),
        response_time_ms: None,
    });

    // Determine overall health status
    let overall_status = determine_overall_status(&database_status, &pool_status, &circuit_breakers);

    let response = DetailedHealthResponse {
        status: overall_status,
        service: "stateset-sequencer",
        version: env!("CARGO_PKG_VERSION"),
        timestamp,
        components: ComponentsHealth {
            database: database_status,
            pool: pool_status,
            circuit_breakers,
            anchor_service: anchor_status,
        },
        system: Some(SystemInfo {
            uptime_secs: None, // Could be added with a startup timestamp
            rust_version: env!("CARGO_PKG_RUST_VERSION"),
        }),
    };

    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still operational
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    Ok((status_code, Json(response)))
}

/// Determine overall health status from component statuses
fn determine_overall_status(
    database: &ComponentStatus,
    pool: &PoolStatus,
    circuit_breakers: &[CircuitBreakerStatus],
) -> HealthStatus {
    // Database is critical
    if database.status.is_unhealthy() {
        return HealthStatus::Unhealthy;
    }

    // Pool critical status is unhealthy
    if pool.status.is_unhealthy() {
        return HealthStatus::Unhealthy;
    }

    // Check for open circuit breakers
    let open_circuits = circuit_breakers
        .iter()
        .filter(|cb| cb.state == "open")
        .count();

    if open_circuits > 0 {
        return HealthStatus::Degraded;
    }

    // Check for degraded components
    if matches!(database.status, HealthStatus::Degraded)
        || matches!(pool.status, HealthStatus::Degraded)
    {
        return HealthStatus::Degraded;
    }

    HealthStatus::Healthy
}

/// Convert PoolHealthStatus to HealthStatus
fn pool_health_to_health_status(status: PoolHealthStatus) -> HealthStatus {
    match status {
        PoolHealthStatus::Healthy | PoolHealthStatus::Moderate => HealthStatus::Healthy,
        PoolHealthStatus::Stressed => HealthStatus::Degraded,
        PoolHealthStatus::Critical => HealthStatus::Unhealthy,
    }
}

/// Convert PoolHealthStatus to string
fn pool_health_to_string(status: PoolHealthStatus) -> &'static str {
    match status {
        PoolHealthStatus::Healthy => "healthy",
        PoolHealthStatus::Moderate => "moderate",
        PoolHealthStatus::Stressed => "stressed",
        PoolHealthStatus::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(!HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Unhealthy.is_healthy());
    }

    #[test]
    fn test_health_status_is_unhealthy() {
        assert!(!HealthStatus::Healthy.is_unhealthy());
        assert!(!HealthStatus::Degraded.is_unhealthy());
        assert!(HealthStatus::Unhealthy.is_unhealthy());
    }

    #[test]
    fn test_determine_overall_status_healthy() {
        let db = ComponentStatus {
            name: "postgresql".to_string(),
            status: HealthStatus::Healthy,
            message: None,
            response_time_ms: Some(10),
        };
        let pool = PoolStatus {
            status: HealthStatus::Healthy,
            total_connections: 10,
            active_connections: 2,
            idle_connections: 8,
            max_connections: 10,
            utilization_percent: 20.0,
            avg_acquisition_ms: Some(5.0),
        };
        let circuit_breakers = vec![];

        assert_eq!(
            determine_overall_status(&db, &pool, &circuit_breakers),
            HealthStatus::Healthy
        );
    }

    #[test]
    fn test_determine_overall_status_unhealthy_db() {
        let db = ComponentStatus {
            name: "postgresql".to_string(),
            status: HealthStatus::Unhealthy,
            message: Some("Connection failed".to_string()),
            response_time_ms: None,
        };
        let pool = PoolStatus {
            status: HealthStatus::Healthy,
            total_connections: 10,
            active_connections: 2,
            idle_connections: 8,
            max_connections: 10,
            utilization_percent: 20.0,
            avg_acquisition_ms: None,
        };
        let circuit_breakers = vec![];

        assert_eq!(
            determine_overall_status(&db, &pool, &circuit_breakers),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn test_determine_overall_status_degraded_circuit() {
        let db = ComponentStatus {
            name: "postgresql".to_string(),
            status: HealthStatus::Healthy,
            message: None,
            response_time_ms: Some(10),
        };
        let pool = PoolStatus {
            status: HealthStatus::Healthy,
            total_connections: 10,
            active_connections: 2,
            idle_connections: 8,
            max_connections: 10,
            utilization_percent: 20.0,
            avg_acquisition_ms: None,
        };
        let circuit_breakers = vec![CircuitBreakerStatus {
            name: "anchor".to_string(),
            state: "open".to_string(),
            successes: 100,
            failures: 5,
            rejected: 10,
        }];

        assert_eq!(
            determine_overall_status(&db, &pool, &circuit_breakers),
            HealthStatus::Degraded
        );
    }

    #[test]
    fn test_pool_health_to_health_status() {
        assert_eq!(
            pool_health_to_health_status(PoolHealthStatus::Healthy),
            HealthStatus::Healthy
        );
        assert_eq!(
            pool_health_to_health_status(PoolHealthStatus::Moderate),
            HealthStatus::Healthy
        );
        assert_eq!(
            pool_health_to_health_status(PoolHealthStatus::Stressed),
            HealthStatus::Degraded
        );
        assert_eq!(
            pool_health_to_health_status(PoolHealthStatus::Critical),
            HealthStatus::Unhealthy
        );
    }
}
