<script lang="ts">
  import type { Snippet } from 'svelte';
  import Logo from '../lib/components/Logo.svelte';
  import LanguageToggle from '../lib/components/LanguageToggle.svelte';

  let { title, children }: { title: string; children: Snippet } = $props();
</script>

<main class="shell">
  <div class="lang"><LanguageToggle /></div>
  <div class="card box">
    <div class="brand"><Logo /> <span>TelltaleDNS</span></div>
    <h1>{title}</h1>
    {@render children()}
  </div>
</main>

<style>
  .shell {
    position: relative;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
  }
  .box {
    width: min(400px, 100%);
    display: grid;
    gap: 14px;
    padding: 24px;
  }
  .lang {
    position: absolute;
    top: 12px;
    right: 12px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    color: var(--muted);
  }
</style>
