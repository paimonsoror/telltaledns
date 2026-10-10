//! RFC 9457 problem details (`application/problem+json`) with a stable `code` and an
//! actionable `hint` (`spec/07` §1, AGT-001).

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Stable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// A parameter is missing, malformed, or out of range.
    InvalidParameter,
    /// No such route or object.
    NotFound,
    /// The `scope` needs clustering.
    UnsupportedScope,
    /// The feature is off or not ready (for example, the query log).
    Unavailable,
    /// A server-side failure; retrying may help.
    Internal,
    /// Not signed in, or the credentials are wrong.
    Unauthorized,
    /// The password was right; a TOTP code (or recovery code) is needed too.
    TotpRequired,
    /// Signed in, but the role or token scope doesn't allow this.
    Forbidden,
    /// A session-authenticated change without a valid `X-CSRF-Token` header.
    CsrfRejected,
    /// Conflicts with existing state (a duplicate name, the last admin).
    Conflict,
    /// The configuration changed since the version in `If-Match`: re-read and retry.
    VersionConflict,
    /// The change is well-formed but the resulting configuration is invalid (the detail
    /// names the field).
    InvalidConfig,
    /// Too many failed sign-ins; wait and retry.
    RateLimited,
    /// The cluster's configuration comes from Git (ADR-048): change it there.
    GitopsManaged,
    /// REQ: OPS-010 — a maintenance window longer than allowed (a day; two hours for agents).
    MaintenanceTooLong,
    /// REQ: OPS-010 — a maintenance request without a usable reason, or shorter than a minute.
    MaintenanceInvalid,
    /// REQ: OPS-010 — the node a request is for isn't reachable over the cluster channel.
    NodeUnreachable,
    /// REQ: OPS-010 — no cluster node by that ID, site, or pod name.
    NodeUnknown,
    /// REQ: OBS-024 — this node is already running a simulation (one at a time per node).
    SimulationBusy,
    /// REQ: OBS-024 — a simulation window that isn't a duration, or is longer than 7 days.
    SimulationWindow,
}

impl Code {
    const fn uri(self) -> &'static str {
        match self {
            Self::InvalidParameter => "https://telltaledns.dev/problems/invalid_parameter",
            Self::NotFound => "https://telltaledns.dev/problems/not_found",
            Self::UnsupportedScope => "https://telltaledns.dev/problems/unsupported_scope",
            Self::Unavailable => "https://telltaledns.dev/problems/unavailable",
            Self::Internal => "https://telltaledns.dev/problems/internal",
            Self::Unauthorized => "https://telltaledns.dev/problems/unauthorized",
            Self::TotpRequired => "https://telltaledns.dev/problems/totp_required",
            Self::Forbidden => "https://telltaledns.dev/problems/forbidden",
            Self::CsrfRejected => "https://telltaledns.dev/problems/csrf_rejected",
            Self::Conflict => "https://telltaledns.dev/problems/conflict",
            Self::RateLimited => "https://telltaledns.dev/problems/rate_limited",
            Self::VersionConflict => "https://telltaledns.dev/problems/version_conflict",
            Self::InvalidConfig => "https://telltaledns.dev/problems/invalid_config",
            Self::GitopsManaged => "https://telltaledns.dev/problems/gitops_managed",
            Self::MaintenanceTooLong => "https://telltaledns.dev/problems/maintenance_too_long",
            Self::MaintenanceInvalid => "https://telltaledns.dev/problems/maintenance_invalid",
            Self::NodeUnreachable => "https://telltaledns.dev/problems/node_unreachable",
            Self::NodeUnknown => "https://telltaledns.dev/problems/node_unknown",
            Self::SimulationBusy => "https://telltaledns.dev/problems/simulation_busy",
            Self::SimulationWindow => "https://telltaledns.dev/problems/simulation_window",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::InvalidParameter => "Invalid parameter",
            Self::NotFound => "Not found",
            Self::UnsupportedScope => "Unsupported scope",
            Self::Unavailable => "Temporarily unavailable",
            Self::Internal => "Internal error",
            Self::Unauthorized => "Authentication required",
            Self::TotpRequired => "Second factor required",
            Self::Forbidden => "Not allowed",
            Self::CsrfRejected => "CSRF check failed",
            Self::Conflict => "Conflict",
            Self::RateLimited => "Too many attempts",
            Self::VersionConflict => "Configuration changed",
            Self::InvalidConfig => "Invalid configuration",
            Self::GitopsManaged => "Managed in Git",
            Self::MaintenanceTooLong => "Maintenance window too long",
            Self::MaintenanceInvalid => "Invalid maintenance request",
            Self::NodeUnreachable => "Node unreachable",
            Self::NodeUnknown => "Unknown node",
            Self::SimulationBusy => "Simulation already running",
            Self::SimulationWindow => "Invalid simulation window",
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidParameter | Self::UnsupportedScope => StatusCode::BAD_REQUEST,
            Self::NotFound | Self::NodeUnknown => StatusCode::NOT_FOUND,
            Self::Unavailable | Self::NodeUnreachable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized | Self::TotpRequired => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::CsrfRejected => StatusCode::FORBIDDEN,
            Self::Conflict | Self::GitopsManaged | Self::SimulationBusy => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::VersionConflict => StatusCode::PRECONDITION_FAILED,
            Self::InvalidConfig
            | Self::MaintenanceTooLong
            | Self::MaintenanceInvalid
            | Self::SimulationWindow => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

/// An API error.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({
    "type": "https://telltaledns.dev/problems/invalid_parameter",
    "title": "Invalid parameter",
    "status": 400,
    "code": "invalid_parameter",
    "detail": "`from`: `yesterday`: expected RFC 3339 time (2026-10-03T12:00:00Z) or a relative offset (-24h)",
    "hint": "Use a relative offset such as -24h, or RFC 3339 such as 2026-10-03T00:00:00Z."
}))]
pub struct Problem {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Short, human-readable summary of the problem type.
    pub title: &'static str,
    /// HTTP status code.
    pub status: u16,
    /// Stable machine-readable code.
    pub code: Code,
    /// What went wrong in this request.
    pub detail: String,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Seconds to wait, sent as `Retry-After` (rate limits).
    #[serde(skip)]
    pub retry_after: Option<u64>,
}

impl Problem {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            kind: code.uri(),
            title: code.title(),
            status: code.status().as_u16(),
            code,
            detail: detail.into(),
            hint: None,
            retry_after: None,
        }
    }

    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Sends `Retry-After: <seconds>` with the problem.
    #[must_use]
    pub fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(Code::InvalidParameter, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(Code::NotFound, detail)
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, detail)
    }

    /// The HTTP status this problem is sent with.
    pub fn code_status(&self) -> StatusCode {
        self.code.status()
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(Code::Internal, detail)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut resp = (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response();
        if let Some(s) = self.retry_after
            && let Ok(v) = header::HeaderValue::from_str(&s.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}
