// REQ: FLT-017 (T15.1) — the Kubernetes workloads, loaded once and kept for a minute, so any
// client chip can tell a workload (by its name, its analytics key, or a pod address) and show
// its glyph and pod. Nothing is fetched when the feature is off.
import { api, type S } from './api';

type Index = {
  /** Workloads by name, analytics key, and pod address. */
  by: Map<string, S['WorkloadInfo']>;
  /** The pod at each address. */
  pods: Map<string, string>;
  at: number;
};

export const workloads = $state<{ items: S['WorkloadInfo'][]; enabled: boolean; index: Index }>({
  items: [],
  enabled: false,
  index: { by: new Map(), pods: new Map(), at: 0 },
});

let pending: Promise<void> | null = null;

function build(items: S['WorkloadInfo'][]): Index {
  const by = new Map<string, S['WorkloadInfo']>();
  const pods = new Map<string, string>();
  for (const w of items) {
    by.set(w.name, w);
    by.set(w.key, w);
    for (const p of w.pods) {
      for (const a of p.addresses) {
        by.set(a, w);
        pods.set(a, p.name);
      }
    }
  }
  return { by, pods, at: Date.now() };
}

/** Loads the workloads (at most once a minute; `force` now). */
export function loadWorkloads(force = false): Promise<void> {
  if (!force && Date.now() - workloads.index.at < 60_000) return Promise.resolve();
  if (pending) return pending;
  pending = (async () => {
    try {
      const st = await api.kubernetesStatus();
      workloads.enabled = st.enabled;
      if (!st.enabled && st.workloads === 0) {
        workloads.items = [];
        workloads.index = build([]);
        return;
      }
      const all: S['WorkloadInfo'][] = [];
      let cursor: string | undefined;
      do {
        const page = await api.workloads(cursor ? { cursor } : {});
        all.push(...page.items);
        cursor = page.nextCursor ?? undefined;
      } while (cursor);
      workloads.items = all;
      workloads.index = build(all);
    } catch {
      // An older node, or no rights: no workloads (chips stay plain).
      workloads.index = { ...workloads.index, at: Date.now() };
    } finally {
      pending = null;
    }
  })();
  return pending;
}

/** The workload a client key, name, or pod address belongs to. */
export function workloadOf(key: string | null | undefined): S['WorkloadInfo'] | undefined {
  return key ? workloads.index.by.get(key) : undefined;
}

/** The pod at an address, when it's a workload's. */
export function podAt(ip: string): string | undefined {
  return workloads.index.pods.get(ip);
}

/** Where a workload's group came from, in words. */
export const groupFromText: Record<string, string> = {
  pod_label: 'pod label',
  namespace_label: 'namespace label',
  map: 'rule',
  default_group: 'default group',
  none: 'network group',
};
