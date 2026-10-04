// REQ: API-011, ADR-036 — Simple or Advanced, remembered per user in this browser. Simple only
// hides technical detail; it never hides something that changes behavior.
import { session } from './session.svelte';

export type Mode = 'simple' | 'advanced';

function key(): string {
  return `telltale.mode.${session.user?.username ?? ''}`;
}

export const mode = $state<{ value: Mode }>({ value: 'simple' });

/** Loads the signed-in user's choice (App calls this whenever the user changes). */
export function loadMode() {
  try {
    mode.value = localStorage.getItem(key()) === 'advanced' ? 'advanced' : 'simple';
  } catch {
    mode.value = 'simple';
  }
}

export function currentMode(): Mode {
  return mode.value;
}

export function setMode(m: Mode) {
  mode.value = m;
  try {
    localStorage.setItem(key(), m);
  } catch {
    // Private mode: the choice lasts for this page only.
  }
}
