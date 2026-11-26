// Dashboard lab — reading a long name the way a person would. A name in a top list is shown by
// the part that says what it is; the rest is a tag, a note, or a click away.
//
//   authentik-postgresql.authentik.svc.cluster.local   → authentik-postgresql  (tag: authentik)
//   api.anthropic.com.claude-sandbox.svc.cluster.local → api.anthropic.com     (tag: search suffix)
//   3dfac2faadc9…ba1.us-east-1.prod.service.….a2z.com  → 3dfac2….us-east-1.prod…
//   4.3.2.1.in-addr.arpa                               → 1.2.3.4               (tag: reverse)
//
// The Kubernetes rules are heuristics on the name alone: the server doesn't know the cluster's
// search list, so a namespace that is also a top-level domain (`io`, `dev`) reads as part of the name.
import { tr } from '../i18n';

const { t } = tr('names');

export interface Parsed {
  /** What to show first. */
  main: string;
  /** A short muted word after it: the namespace, or what was added. */
  tag: string;
  /** One sentence for the tooltip and the detail panel, when the display differs from the name. */
  note: string;
  kind: 'plain' | 'service' | 'expansion' | 'reverse';
}

const TLD = /^(com|net|org|io|dev|app|edu|gov|cloud|info|biz|co|[a-z]{2})$/;
const HEXY = /^[0-9a-f]{16,}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A long hash or UUID label shortened to its first characters. */
function elide(label: string): string {
  return HEXY.test(label) || UUID.test(label) ? `${label.slice(0, 6)}…` : label;
}

function ip6(nibbles: string[]): string {
  const hex = nibbles.slice().reverse().join('');
  const groups = (hex.match(/.{4}/g) ?? []).map((g) => g.replace(/^0+(?=.)/, ''));
  // Collapse the longest run of zero groups, as people write addresses.
  let best = { at: -1, len: 0 };
  for (let i = 0; i < groups.length; ) {
    if (groups[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < groups.length && groups[j] === '0') j++;
    if (j - i > best.len) best = { at: i, len: j - i };
    i = j;
  }
  if (best.len < 2) return groups.join(':');
  const left = groups.slice(0, best.at).join(':');
  const right = groups.slice(best.at + best.len).join(':');
  return `${left}::${right}`;
}

export function parseName(raw: string): Parsed {
  const n = raw.replace(/\.$/, '').toLowerCase();
  const plain = (s: string): Parsed => ({ main: s.split('.').map(elide).join('.'), tag: '', note: '', kind: 'plain' });
  // REQ: API-012 — the tag and the note are display text; `kind` says what the name is.
  const reverse = (a: string): Parsed => ({ main: a, tag: t('reverse'), note: t('Reverse lookup of {address}', { address: a }), kind: 'reverse' });

  // Reverse lookups: the address, not the nibbles.
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/.exec(n);
  if (v4) return reverse(`${v4[4]}.${v4[3]}.${v4[2]}.${v4[1]}`);
  if (n.endsWith('.ip6.arpa')) {
    const nib = n.slice(0, -'.ip6.arpa'.length).split('.');
    if (nib.length === 32 && nib.every((x) => /^[0-9a-f]$/.test(x))) return reverse(ip6(nib));
  }

  if (n.endsWith('.cluster.local')) {
    const rest = n.slice(0, -'.cluster.local'.length);
    // service.namespace.svc: a Kubernetes service, by its own name.
    const svc = /^([a-z0-9-]+)\.([a-z0-9-]+)\.svc$/.exec(rest);
    if (svc) {
      return { main: svc[1], tag: svc[2], note: t('Kubernetes service {service} in the {namespace} namespace', { service: svc[1], namespace: svc[2] }), kind: 'service' };
    }
    // Anything else was a real name that a pod's DNS search list extended. Strip the suffix it tried
    // (.<namespace>.svc, .svc, or none) to find what was asked for.
    let real = rest;
    const ns = /^(.+)\.([a-z0-9-]+)\.svc$/.exec(rest);
    if (ns && ns[2] !== 'svc' && !TLD.test(ns[2])) real = ns[1];
    else if (rest.endsWith('.svc')) real = rest.slice(0, -4);
    if (real.includes('.')) {
      const added = n.slice(real.length);
      const inner = /^([a-z0-9-]+)\.([a-z0-9-]+)\.svc$/.exec(real);
      if (inner) {
        return {
          main: inner[1],
          tag: inner[2],
          note: t("Kubernetes service {service} in {namespace}, with the search suffix {suffix} added by a pod's DNS settings", { service: inner[1], namespace: inner[2], suffix: added }),
          kind: 'expansion',
        };
      }
      return {
        main: real.split('.').map(elide).join('.'),
        tag: t('search suffix'),
        note: t("{name}, with the search suffix {suffix} added by a pod's DNS settings (the real name is usually asked next)", { name: real, suffix: added }),
        kind: 'expansion',
      };
    }
  }
  return plain(n);
}

/** A pod's own name shortened to its workload's: `app-7c9d8f6b5-x2x9k` → `app` (the full name stays in the detail panel). */
export function workloadName(name: string): string {
  const m = /^(.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$/.exec(name);
  return m ? m[1] : name;
}
