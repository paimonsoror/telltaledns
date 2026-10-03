//! Wiring for the list fetcher (`spec/05` §3.4): startup, reload, and `telltale lists fetch`.
//!
//! REQ: FLT-004. The fetcher only runs where lists are compiled: role `all` or `controller`.
//! Failures here are logged and never affect DNS (AGENTS.md rule 5).

use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use telltale_config::{Config, Role};
use telltale_filter::fetch::{
    Client, FetchSettings, Fetcher, ListSpec, Outcome, Resolve, Store, SystemResolver,
};
use telltale_upstream::Bootstrap;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Resolves list hostnames like hostname upstreams do (UPS-009): through the system resolvers
/// minus our own listeners. When the system resolver *is* this server (a Pi pointing
/// `/etc/resolv.conf` at itself), fall back to the OS resolver, which then asks our own
/// listeners. That's safe: a list download is an HTTP client, not a forwarder, so it can't
/// loop, and the listeners are bound before the fetcher starts.
struct ListResolver {
    bootstrap: Option<Bootstrap>,
}

impl ListResolver {
    fn new(listen: &[SocketAddr]) -> Self {
        let b = Bootstrap::system(listen);
        Self {
            bootstrap: (!b.servers().is_empty()).then_some(b),
        }
    }
}

impl Resolve for ListResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(b) = &self.bootstrap
                && let Ok(ips) = b.resolve(host).await
            {
                return Ok(ips);
            }
            SystemResolver.resolve(host).await
        })
    }
}

fn build_fetcher(cfg: &Config) -> Result<Arc<Fetcher>, String> {
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let store = Store::open(data_dir).map_err(|e| format!("{}/lists: {e}", data_dir.display()))?;
    let listen: Vec<SocketAddr> = cfg.listen.iter().map(|l| l.addr).collect();
    let client = Client::new(Arc::new(ListResolver::new(&listen)), &[])?;
    Ok(Arc::new(Fetcher::new(
        store,
        client,
        FetchSettings::from_config(cfg),
    )))
}

/// The running fetcher.
pub(crate) struct Lists {
    pub(crate) fetcher: Arc<Fetcher>,
    specs: watch::Sender<Arc<Vec<ListSpec>>>,
    /// Bumped when stored list content changes.
    #[expect(dead_code, reason = "the list compiler (T2.3) subscribes")]
    pub(crate) changed: watch::Receiver<u64>,
    task: JoinHandle<()>,
}

impl Lists {
    /// Starts the background fetcher if this node compiles lists and any are configured.
    pub(crate) fn start(cfg: &Config) -> Option<Self> {
        if cfg.node.role == Role::Resolver || cfg.list.is_empty() {
            return None;
        }
        let fetcher = match build_fetcher(cfg) {
            Ok(f) => f,
            Err(e) => {
                error!("lists: {e}; lists won't be downloaded (DNS is unaffected)");
                return None;
            }
        };
        let specs = ListSpec::from_config(cfg);
        info!(
            lists = specs.len(),
            dir = %fetcher.store().dir().display(),
            "list fetcher started"
        );
        let (specs_tx, specs_rx) = watch::channel(Arc::new(specs));
        let (changed_tx, changed) = watch::channel(0);
        let task = tokio::spawn(Arc::clone(&fetcher).run(specs_rx, changed_tx));
        Some(Self {
            fetcher,
            specs: specs_tx,
            changed,
            task,
        })
    }

    /// Applies a reloaded config: new, removed, or edited lists take effect at once.
    /// Fetch settings (`[filter]`) and `data_dir` need a restart.
    pub(crate) fn reload(&self, cfg: &Config) {
        let specs = ListSpec::from_config(cfg);
        self.specs.send_if_modified(|cur| {
            if **cur == specs {
                false
            } else {
                *cur = Arc::new(specs);
                true
            }
        });
    }

    pub(crate) fn stop(self) {
        self.task.abort();
    }
}

/// `telltale lists fetch`: refresh every enabled list once and print the result.
pub(crate) async fn fetch_once(cfg: &Config, out: &mut dyn Write) -> Result<bool, String> {
    let fetcher = build_fetcher(cfg)?;
    let specs = ListSpec::from_config(cfg);
    if specs.is_empty() {
        writeln!(out, "no enabled lists in the configuration").map_err(|e| e.to_string())?;
        return Ok(true);
    }
    let results = fetcher.refresh(&specs).await;
    let status = fetcher.status();
    let mut all_ok = true;
    writeln!(
        out,
        "{:<24} {:<10} {:>12} {:>10}  note",
        "list", "result", "bytes", "lines"
    )
    .map_err(|e| e.to_string())?;
    for (name, outcome) in &results {
        let meta = status
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, m)| m.clone())
            .unwrap_or_default();
        let (result, note) = match outcome {
            Outcome::Updated => ("updated", String::new()),
            Outcome::Unchanged => ("unchanged", String::new()),
            Outcome::Failed(e) => {
                all_ok = false;
                let kept = if meta.has_content() {
                    " (kept previous copy)"
                } else {
                    ""
                };
                ("FAILED", format!("{e}{kept}"))
            }
        };
        writeln!(
            out,
            "{name:<24} {result:<10} {:>12} {:>10}  {note}",
            meta.bytes, meta.lines
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(out, "stored in {}", fetcher.store().dir().display()).map_err(|e| e.to_string())?;
    Ok(all_ok)
}
