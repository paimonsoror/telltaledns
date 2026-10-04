<script lang="ts">
  import HelpButton from '../lib/components/HelpButton.svelte';
</script>

<div class="page">
  <h1>Local DNS<HelpButton id="local-dns" /></h1>
  <div class="notice">
    <p>
      Local records (A, AAAA, CNAME, PTR, TXT, MX, SRV, wildcards) and hosts files are set in the
      configuration with <code>[[record]]</code> and <code>[local]</code>, then applied with a reload
      (<code>SIGHUP</code>). Viewing and editing them here arrives with the configuration API.
    </p>
    <pre class="mono">[[record]]
name = "nas.home.arpa"
type = "A"
value = "192.168.1.10"</pre>
  </div>
</div>

<style>
  pre {
    background: var(--surface-2);
    padding: 10px 12px;
    border-radius: 8px;
    overflow-x: auto;
    margin: 8px 0 0;
  }
</style>
