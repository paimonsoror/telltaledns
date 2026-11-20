<script lang="ts">
  // REQ: OBS-039 (ADR-167) — a small mark left of a domain name, drawn from what the UI already
  // knows: no request is made for it, so nothing about a person's queries leaves the page.
  //  - A name the brand map knows gets the brand's colour and glyph (Simple Icons, CC0; Bootstrap Icons, MIT,
  //    for the marks Simple Icons dropped: its glyphs sit on a 16 grid, the others on 24).
  //  - Every other name gets a monogram in a stable colour: the same owner is always the same
  //    colour. "Monogram only" gives every name one, and never loads the brand glyphs.
  //  - A name of the network itself (.arpa, .lan, .local, Kubernetes) gets a quiet house.
  //  - A name the privacy level hid (a hash) gets nothing; "Off" draws nothing at all.
  // Decorative: the name beside it is the label, so it is hidden from screen readers.
  //
  // One saturated thing in a list: brand tiles carry the colour, so a recognisable name is found
  // at a glance; monograms are low-chroma tints at one lightness, so no hue outweighs another and
  // the rest recedes. Near-black marks flip to a light tile in the dark theme, where black would
  // vanish. A blocked name wears the same mark with most of its colour drained.
  import { brandFor, brandTitle, registrable, hueOf, letterOf, isInternal, isHashed, inkFor, luminance } from './map';
  import { brandData, ensureBrands } from './brands.svelte';
  import { iconPrefs } from './prefs.svelte';
  import { ICON_PX } from './prefs';

  let { name, quiet = false }: { name: string; quiet?: boolean } = $props();

  const shown = $derived(iconPrefs.style !== 'off' && !isHashed(name));
  const size = $derived(ICON_PX[iconPrefs.size]);
  const slug = $derived(shown && iconPrefs.style === 'brand' ? brandFor(name) : null);
  $effect(() => {
    if (slug) ensureBrands();
  });
  const glyph = $derived(slug ? brandData.data[slug] : undefined);
  const reg = $derived(registrable(name));
  const hue = $derived(hueOf(reg));
  const letter = $derived(letterOf(reg));
  const hex = $derived(glyph?.[0] ?? '000000');
  const dim = $derived(!!glyph && luminance(hex) < 0.05);
  const grid = $derived(glyph?.[2] ?? 24);

  type Kind = 'brand' | 'wait' | 'house' | 'mono';
  const kind = $derived.by((): Kind => {
    if (slug) return glyph ? 'brand' : 'wait';
    return isInternal(name) ? 'house' : 'mono';
  });
  const inner = $derived(Math.round(size * 0.6));
</script>

{#if shown}
  <span
    class="ic {kind}"
    class:dim
    class:quiet
    data-testid="domain-icon"
    data-kind={kind}
    data-size={size}
    style:--s="{size}px"
    style:--h={hue}
    style:--bg={'#' + hex}
    style:--ink={inkFor(hex)}
    title={slug ? brandTitle(slug) : undefined}
    aria-hidden="true"
  >
    {#if kind === 'brand' && glyph}
      <svg viewBox="0 0 {grid} {grid}" width={inner} height={inner} fill="currentColor"><path d={glyph[1]} /></svg>
    {:else if kind === 'house'}
      <svg viewBox="0 0 24 24" width={inner} height={inner} fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11.5 12 4l8 7.5V20a1 1 0 0 1-1 1h-4.5v-6h-5v6H5a1 1 0 0 1-1-1z" /></svg>
    {:else if kind === 'mono'}
      {letter}
    {/if}
  </span>
{/if}

<style>
  .ic {
    flex: none;
    display: inline-grid;
    place-items: center;
    box-sizing: border-box;
    width: var(--s);
    height: var(--s);
    border-radius: calc(var(--s) * 0.28);
    font-size: calc(var(--s) * 0.5);
    font-weight: 650;
    line-height: 1;
    font-family: inherit;
    letter-spacing: 0;
    user-select: none;
    vertical-align: middle;
  }
  /* A monogram: one lightness and one chroma for every hue, so none outweighs another. */
  .mono {
    background: oklch(0.935 0.04 var(--h));
    color: oklch(0.42 0.11 var(--h));
  }
  .brand {
    background: var(--bg);
    color: var(--ink);
    box-shadow: inset 0 0 0 1px rgb(0 0 0 / 10%);
  }
  .house {
    background: var(--surface-2);
    color: var(--muted);
  }
  .wait {
    background: var(--surface-2);
  }
  .quiet {
    filter: saturate(0.3);
    opacity: 0.8;
  }
  :global(:root[data-theme='dark']) .mono {
    background: oklch(0.32 0.05 var(--h));
    color: oklch(0.86 0.1 var(--h));
  }
  :global(:root[data-theme='dark']) .brand {
    box-shadow: inset 0 0 0 1px rgb(255 255 255 / 16%);
  }
  :global(:root[data-theme='dark']) .brand.dim {
    background: var(--text);
    color: #111418;
  }
  @media (prefers-color-scheme: dark) {
    :global(:root:not([data-theme='light'])) .mono {
      background: oklch(0.32 0.05 var(--h));
      color: oklch(0.86 0.1 var(--h));
    }
    :global(:root:not([data-theme='light'])) .brand {
      box-shadow: inset 0 0 0 1px rgb(255 255 255 / 16%);
    }
    :global(:root:not([data-theme='light'])) .brand.dim {
      background: var(--text);
      color: #111418;
    }
  }
</style>
