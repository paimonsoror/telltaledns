//! What kind of device each address is (REQ: OBS-025; T13.3, ADR-117).

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;

use crate::Shared;
use crate::model::{DeviceIdentity, Items};
use crate::problem::Problem;

pub(crate) fn routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/clients/identities", get(identities))
        .route("/api/v1/clients/{id}/identity", get(identity))
        .with_state(backend)
}

/// What each device looks like (OBS-025).
///
/// One row per device seen in the last day (every node's, in a cluster: the most confident
/// guess per device): the product (`Roku player`), its class (`streaming`), how sure
/// (`likely` from a score of 0.6, `possibly` from 0.35, else `unknown` with the MAC vendor
/// alone), the vendor, and `suggestedGroup` when a group's `device_classes` asks for it. A
/// device's `[[client]] kind` wins (`source: override`). Guessed from the MAC vendor, the names
/// the device announces, and the domains it talks to; it never changes how a query is
/// answered. Empty at query-log privacy level 1 and above, or with `[identify] enabled = false`.
#[utoipa::path(get, path = "/api/v1/clients/identities", tag = "config",
    responses((status = 200, body = Items<DeviceIdentity>, description = "The identities, by device.")))]
pub(crate) async fn identities(State(b): State<Shared>) -> Json<Items<DeviceIdentity>> {
    let (items, missing_nodes) =
        tokio::task::spawn_blocking(move || (b.identities(), b.missing_nodes()))
            .await
            .unwrap_or_default();
    Json(Items {
        items,
        missing_nodes,
    })
}

/// What one device looks like, and why (OBS-025).
///
/// `id` is the device's address, or a named device's name (its first address). The answer
/// carries the evidence: the signature's domains the device talked to and their weights, the
/// MAC prefix and vendor, the announced name that matched, every name and domain seen, and a
/// runner-up within 0.1 ("could also be …"). `available: false` with `reason`: `disabled`,
/// `privacy_level`, or `not_seen` (no queries from it in the last day).
#[utoipa::path(get, path = "/api/v1/clients/{id}/identity", tag = "config",
    params(("id" = String, Path, description = "An address, or a named device's name.")),
    responses(
        (status = 200, body = DeviceIdentity, description = "The identity and its evidence."),
        (status = 404, body = Problem, description = "No named device by that name, and not an address."),
    ))]
pub(crate) async fn identity(
    State(b): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<DeviceIdentity>, Problem> {
    tokio::task::spawn_blocking(move || b.identity(&id))
        .await
        .map_err(|e| Problem::internal(format!("request worker failed: {e}")))?
        .map(Json)
}
