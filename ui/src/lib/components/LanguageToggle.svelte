<script lang="ts">
  // REQ: API-005, API-011 — the language switch: one button that names the other language, so it
  // fits beside the theme switch on a phone. The choice is kept in this browser (i18n/locale).
  import Icon from './Icon.svelte';
  import { i18n, localeName, setLocale, t, type Locale } from '../i18n';

  const next = $derived<Locale>(i18n.locale === 'zh-CN' ? 'en' : 'zh-CN');
  const label = $derived(`${t('common.switchLanguage')}: ${localeName(next)}`);
</script>

<button
  class="icon-btn lang"
  type="button"
  title={label}
  aria-label={label}
  data-testid="language-toggle"
  onclick={() => setLocale(next)}
>
  <Icon name="globe" />
  <span class="code" aria-hidden="true">{next === 'zh-CN' ? '中' : 'EN'}</span>
</button>

<style>
  /* `button.icon-btn` in app.css sets a square 36 px button: be more specific. */
  button.lang {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    width: auto;
    min-width: 44px;
    padding: 0 8px;
  }
  .code {
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
  }
  @media (max-width: 760px) {
    button.lang {
      min-width: 34px;
      padding: 0 4px;
    }
    button.lang :global(svg) {
      display: none;
    }
  }
</style>