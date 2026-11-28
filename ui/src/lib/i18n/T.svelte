<!-- REQ: API-012 (ADR-189) — a whole sentence with markup inside it, as one message:
  <T ctx="anomalies" msg={'Muted by <b>{who}</b>: not counted'} params={{ who }}>
    {#snippet b(text)}<b>{text}</b>{/snippet}
  </T>
  The message is an expression: in a quoted attribute Svelte would substitute {who} itself. It is
  split on the tags the caller has snippets for; every piece is text or goes through that snippet.
  Translated text never becomes markup (no {@html}); an unknown tag stays text. -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { lookup } from './index';
  import { parts, type Params } from './message';

  type Props = { ctx: string; msg: string; params?: Params; note?: string; [tag: string]: unknown };
  let { ctx, msg, params, note, ...rest }: Props = $props();
  const snippets = $derived(Object.fromEntries(Object.entries(rest).filter(([, v]) => typeof v === 'function')) as Record<string, Snippet<[string]>>);
  const pieces = $derived(parts(lookup(ctx, msg, note), params, Object.keys(snippets)));
</script>

{#each pieces as p}{#if p.tag}{@render snippets[p.tag](p.text)}{:else}{p.text}{/if}{/each}
