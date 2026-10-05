//! REQ: DNS-006, API-005 (T6.13) — the cache: counters per node, what it holds for a name,
//! and flushing a name, a subtree, or everything, on every node (or one). Reads need a viewer;
//! a flush needs an operator (agents: `ops:cache`) and is audit-logged as `cache.flush`.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::model::{CacheFlushRequest, CacheFlushResult, CacheLookup, CacheNodeStats, Items};
use crate::problem::Problem;
use crate::{Backend, Shared};

/// Reads (viewer).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/cache/stats", get(stats))
        .route("/api/v1/cache/lookup", get(lookup))
        .with_state(backend)
}

/// The flush (operator).
pub(crate) fn flush_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/cache/flush", post(flush))
        .with_state((backend, auth))
}

/// Cache counters, per node.
///
/// For each node (this one first): entries, memory, hits, misses, the hit rate, stale answers
/// served, prefetches, evictions, and answers that couldn't be cached. Each node has its own
/// cache, so a cluster shows one row per node.
#[utoipa::path(get, path = "/api/v1/cache/stats", tag = "system",
    responses((status = 200, body = Items<CacheNodeStats>, description = "One row per node.")))]
async fn stats(State(b): State<Shared>) -> Response {
    let rows = tokio::task::spawn_blocking(move || b.cache_stats()).await;
    match rows {
        Ok(items) => Json(Items {
            missing_nodes: Vec::new(),
            items,
        })
        .into_response(),
        Err(e) => Problem::internal(format!("cache stats: {e}")).into_response(),
    }
}

/// `?name=` for a lookup.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LookupParams {
    /// The name to look up, e.g. `www.example.com`.
    pub name: String,
}

/// What the cache holds for a name, on every node.
///
/// Each cached answer for exactly `name` (every query type, and the variants for clients that
/// set DO or CD), with the node that holds it, its response code, answer count, whether it was
/// DNSSEC-validated, how long it stays fresh (negative: how long it has been stale), its age,
/// size, and hits. Looking doesn't count as a hit or change anything. Blocked answers are never
/// cached, so they don't appear.
#[utoipa::path(get, path = "/api/v1/cache/lookup", tag = "system",
    params(LookupParams),
    responses(
        (status = 200, body = CacheLookup, description = "The cached answers (empty when there are none)."),
        (status = 400, body = Problem, description = "Not a domain name."),
    ))]
async fn lookup(State(b): State<Shared>, Query(p): Query<LookupParams>) -> Response {
    let name = p.name.clone();
    match tokio::task::spawn_blocking(move || b.cache_lookup(&name)).await {
        Ok(Ok(entries)) => Json(CacheLookup {
            name: p.name,
            entries,
        })
        .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("cache lookup: {e}")).into_response(),
    }
}

/// Flush the cache: one name, a subtree, or everything.
///
/// With `name`, removes that name's cached answers (with `subtree`, every name under it too);
/// without, empties the cache. By default every node in the cluster flushes; `node` limits it to
/// one. The next query for a flushed name is asked of the upstreams again. This doesn't clear
/// devices' own caches, blocked answers are never cached (unblocking needs no flush), and to
/// change what a name resolves to, use local names instead. Needs the operator role (or the
/// `ops:cache` agent scope); audit-logged as `cache.flush`.
#[utoipa::path(post, path = "/api/v1/cache/flush", tag = "system",
    request_body = CacheFlushRequest,
    responses(
        (status = 200, body = CacheFlushResult, description = "What each node removed."),
        (status = 400, body = Problem, description = "Not a domain name, or an unknown node."),
    ))]
async fn flush(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<CacheFlushRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let r = req.clone();
    let b2: Arc<dyn Backend> = Arc::clone(&backend);
    let result = tokio::task::spawn_blocking(move || {
        b2.cache_flush(
            r.name.as_deref(),
            r.subtree.unwrap_or(false),
            r.node.as_deref(),
        )
    })
    .await;
    match result {
        Ok(Ok(nodes)) => {
            let total_removed = nodes.iter().filter_map(|n| n.removed).sum();
            let out = CacheFlushResult {
                total_removed,
                nodes,
            };
            let target = req.name.clone().unwrap_or_else(|| "*".into());
            auth.record(
                &actor,
                "cache.flush",
                &target,
                &serde_json::json!({ "subtree": req.subtree.unwrap_or(false), "node": req.node, "removed": total_removed }),
            );
            Json(out).into_response()
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("cache flush: {e}")).into_response(),
    }
}
