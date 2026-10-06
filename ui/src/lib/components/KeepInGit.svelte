<script lang="ts">
  // REQ: API-002 (T7.5, ADR-069) — on a node whose configuration comes from Git: what to add
  // to the repository (or the Helm values' `config:`) to keep a change made here.
  let { toml }: { toml: string } = $props();
  let copied = $state(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(toml);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      // Clipboard access can be refused (plain HTTP): the text is selectable anyway.
    }
  }
</script>

<div class="keep" data-testid="keep-in-git">
  <div class="head">
    <strong>Keep it in Git</strong>
    <button class="link small" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
  </div>
  <p class="small muted">
    This node's configuration comes from Git. The change is saved on this node and shared with the cluster, but a
    rebuild from Git won't have it until you add this:
  </p>
  <pre class="mono small">{toml}</pre>
</div>

<style>
  .keep {
    border: 1px solid var(--info, var(--border));
    border-radius: 8px;
    padding: 10px 12px;
    background: color-mix(in srgb, var(--info, var(--accent)) 7%, transparent);
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  p {
    margin: 4px 0 6px;
  }
  pre {
    margin: 0;
    padding: 8px;
    overflow-x: auto;
    background: var(--surface);
    border-radius: 6px;
    white-space: pre;
  }
</style>
