/** Runs `f` now and every `ms` while the page is visible; returns a stop function. */
export function poll(f: () => Promise<unknown> | void, ms: number): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  const tick = async () => {
    if (stopped) return;
    if (document.visibilityState === 'visible') {
      try {
        await f();
      } catch {
        // Errors are shown by the caller; keep polling.
      }
    }
    if (!stopped) timer = setTimeout(tick, ms);
  };
  const onVisible = () => {
    if (document.visibilityState === 'visible' && !stopped) {
      clearTimeout(timer);
      void tick();
    }
  };
  document.addEventListener('visibilitychange', onVisible);
  void tick();
  return () => {
    stopped = true;
    clearTimeout(timer);
    document.removeEventListener('visibilitychange', onVisible);
  };
}
