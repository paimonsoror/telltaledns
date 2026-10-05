<script lang="ts">
  // T6.8 — an inline share bar for table cells: the number stays the text, this is the picture.
  let { value, color = '--accent', label = '' }: { value: number | null | undefined; color?: string; label?: string } = $props();
  const w = $derived(Math.min(100, Math.max(0, Number.isFinite(value ?? NaN) ? (value as number) : 0)));
</script>

<span class="share" title={label || `${w.toFixed(w < 10 ? 1 : 0)}%`} aria-hidden="true">
  <span style:width={`${w}%`} style:background={`var(${color})`}></span>
</span>

<style>
  .share {
    display: block;
    height: 4px;
    margin-top: 5px;
    margin-left: auto;
    max-width: 120px;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .share span {
    display: block;
    height: 100%;
    border-radius: 999px;
  }
</style>
