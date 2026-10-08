// REQ: OBS-015 — the cluster's health (healthy, degraded, severe), polled once for the whole UI:
// the sidebar's health icon and the phone menu's dot read it.
import { api, type S } from './api';
import { poll } from './poll';

export const health = $state<{ value: S['Health'] | null }>({ value: null });

/** Starts polling every 30 s; returns the stop function. */
export function watchHealth(): () => void {
  return poll(async () => {
    health.value = await api.health();
  }, 30_000);
}
