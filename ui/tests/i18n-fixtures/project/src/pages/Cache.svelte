<!-- A fixture for tests/e2e/7-i18n.spec.ts (API-012): a page on the translation layer. Never built. -->
<script lang="ts">
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  import { num } from '../lib/format';
  const { t, tn } = tr('cache');
  const { t: tc } = tr('common');
  let { n = 2, who = 'admin' }: { n?: number; who?: string } = $props();
</script>

<h2>{t('Holds')}</h2>
<p>{tn('{n} answer', '{n} answers', n, { n: num(n) })}</p>
<p>{t('Read https://example.com/docs first.')}</p>
<p>{t('Sends mail to smtp://mail.example:587')}</p>
<p>{t('Choose email or ntfy')}</p>
<p>{t('Notify by {kind}', { kind: 'email' })}</p>
<button aria-label={tc('Save')}>{tc('Save')}</button>
<T ctx="cache" msg={'Kept by <b>{who}</b>'} params={{ who }}>{#snippet b(text)}<b>{text}</b>{/snippet}</T>
