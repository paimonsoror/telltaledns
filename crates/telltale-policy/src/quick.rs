//! REQ: FLT-005, FLT-013 (T6.12, ADR-067) — quick rules: allow or block a domain (and its
//! subdomains) for some devices, some groups, or everyone, optionally until a time. They form
//! their own layer, checked before the lists: among the rules that match the query name and
//! apply to the client, a device rule beats a group rule beats an everyone rule; within one
//! scope the longer domain wins, then allow beats block.
//!
//! Lookups lowercase the query name into a stack buffer and probe each suffix in a hash map
//! (at most one probe per label); nothing is allocated. With no rules it's one branch.

use std::collections::HashMap;
use std::net::IpAddr;

use telltale_config::{Cidr, Config, RuleAction};

use crate::clients::{ClientTable, Identity};

/// Who a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleScope {
    /// Named devices (client indices) and addresses.
    Devices {
        clients: Vec<u16>,
        nets: Vec<Cidr>,
    },
    /// Group indices.
    Groups(Vec<u16>),
    Everyone,
}

impl RuleScope {
    /// Device > group > everyone.
    fn rank(&self) -> u8 {
        match self {
            Self::Devices { .. } => 3,
            Self::Groups(_) => 2,
            Self::Everyone => 1,
        }
    }
}

/// One rule, ready for lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickRule {
    pub id: Box<str>,
    pub allow: bool,
    /// Lowercase, without the final dot.
    pub domain: Box<str>,
    pub scope: RuleScope,
    /// Unix seconds; the rule stops applying at this time.
    pub expires: Option<i64>,
    pub note: Option<Box<str>>,
    /// The scope as written (device names, addresses, group names), for explanations.
    pub targets: Vec<Box<str>>,
    labels: u8,
}

/// What decided, for attribution: the rule's index in [`QuickRules::rules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuickMatch {
    pub allow: bool,
    pub rule: u32,
}

/// The rules of one configuration, indexed by domain (lowercase wire format).
#[derive(Debug, Default, Clone)]
pub struct QuickRules {
    rules: Vec<QuickRule>,
    by_domain: HashMap<Box<[u8]>, Vec<u32>>,
}

/// `example.com` → `\x07example\x03com\x00` (the wire form a query name has).
fn wire(domain: &str) -> Option<Box<[u8]>> {
    let mut out = Vec::with_capacity(domain.len() + 2);
    for label in domain.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| *l > 0 && *l < 64)?;
        out.push(len);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    (out.len() <= 255).then(|| out.into_boxed_slice())
}

impl QuickRules {
    /// Builds the table from a validated configuration and the client table built from it.
    /// Unknown device names and groups are skipped (validation reports them).
    pub fn from_config(cfg: &Config, clients: &ClientTable) -> Self {
        let mut t = Self::default();
        for r in &cfg.rule {
            let domain = r.domain.trim_end_matches('.').to_ascii_lowercase();
            let Some(key) = wire(&domain) else { continue };
            let scope = if !r.devices.is_empty() {
                let mut ids = Vec::new();
                let mut nets = Vec::new();
                for d in &r.devices {
                    if let Some(i) = clients
                        .clients()
                        .iter()
                        .position(|c| c.name.eq_ignore_ascii_case(d))
                    {
                        ids.extend(u16::try_from(i));
                    } else if let Ok(net) = Cidr::parse(d) {
                        nets.push(net);
                    }
                }
                RuleScope::Devices { clients: ids, nets }
            } else if !r.groups.is_empty() {
                let ids = r
                    .groups
                    .iter()
                    .filter_map(|g| {
                        clients
                            .groups()
                            .iter()
                            .position(|x| x.name.as_ref() == g.as_str())
                    })
                    .filter_map(|i| u16::try_from(i).ok())
                    .collect();
                RuleScope::Groups(ids)
            } else {
                RuleScope::Everyone
            };
            let idx = u32::try_from(t.rules.len()).unwrap_or(u32::MAX);
            t.rules.push(QuickRule {
                id: r.id.as_str().into(),
                allow: r.action == RuleAction::Allow,
                labels: u8::try_from(domain.split('.').count()).unwrap_or(u8::MAX),
                domain: domain.into(),
                scope,
                expires: r
                    .expires
                    .as_deref()
                    .and_then(telltale_config::parse_rfc3339),
                note: r.note.as_deref().map(Into::into),
                targets: r
                    .devices
                    .iter()
                    .chain(&r.groups)
                    .map(|s| s.as_str().into())
                    .collect(),
            });
            t.by_domain.entry(key).or_default().push(idx);
        }
        t
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rule a query-log reference names ([`quick_ref`]), if it still exists.
    pub fn by_ref(&self, r: u16) -> Option<&QuickRule> {
        self.rules.iter().find(|q| quick_ref(&q.id) == r)
    }

    pub fn rules(&self) -> &[QuickRule] {
        &self.rules
    }

    /// The deciding rule for `qname` (wire format) asked by a client, at `now` (Unix
    /// seconds), or `None` to let the lists decide. Allocation-free.
    pub fn decide(
        &self,
        qname: &[u8],
        who: Identity,
        peer: IpAddr,
        groups: &[u16],
        now: i64,
    ) -> Option<QuickMatch> {
        if self.rules.is_empty() || qname.len() > 255 {
            return None;
        }
        let mut buf = [0u8; 255];
        let name = &mut buf[..qname.len()];
        name.copy_from_slice(qname);
        name.make_ascii_lowercase();
        let mut best: Option<((u8, u8, bool), u32)> = None;
        let mut at = 0usize;
        while at < name.len() {
            if let Some(ids) = self.by_domain.get(&name[at..]) {
                for &i in ids {
                    let Some(r) = self.rules.get(i as usize) else {
                        continue;
                    };
                    if r.expires.is_some_and(|e| now >= e) || !applies(&r.scope, who, peer, groups)
                    {
                        continue;
                    }
                    let rank = (r.scope.rank(), r.labels, r.allow);
                    if best.is_none_or(|(b, _)| rank > b) {
                        best = Some((rank, i));
                    }
                }
            }
            let len = usize::from(name[at]);
            if len == 0 {
                break;
            }
            at += len + 1;
        }
        best.map(|((_, _, allow), rule)| QuickMatch { allow, rule })
    }

    /// Rules whose expiry has passed at `now`, by ID (for the sweep that deletes them).
    pub fn expired(&self, now: i64) -> Vec<Box<str>> {
        self.rules
            .iter()
            .filter(|r| r.expires.is_some_and(|e| now >= e))
            .map(|r| r.id.clone())
            .collect()
    }
}

/// A rule's 16-bit reference in query events: FNV-1a of its ID, folded. Stable while the rule
/// exists, whatever happens to the others (positions aren't).
pub fn quick_ref(id: &str) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for b in id.bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    u16::try_from((h >> 16) ^ (h & 0xffff)).unwrap_or(0)
}

fn applies(scope: &RuleScope, who: Identity, peer: IpAddr, groups: &[u16]) -> bool {
    match scope {
        RuleScope::Everyone => true,
        RuleScope::Groups(ids) => ids.iter().any(|g| groups.contains(g)),
        RuleScope::Devices { clients, nets } => {
            who.client.is_some_and(|c| clients.contains(&c))
                || nets.iter().any(|n| n.contains(peer))
        }
    }
}

#[cfg(test)]
mod tests;
