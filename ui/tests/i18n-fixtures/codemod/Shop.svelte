<!-- A fixture for tests/e2e/7-i18n-codemod.spec.ts (API-012): a made-up page before the codemod.
     Never built. It holds what the codemod moves and what it lists for the hand. -->
<script lang="ts">
  let { n = 2, rows = ['a', 'b'], open = true }: { n?: number; rows?: string[]; open?: boolean } = $props();
  const kinds = [{ id: 'all', label: 'All kinds' }];
  const word = n === 1 ? 'basket' : 'baskets';
</script>

<h1>Corner   shop</h1>
<p class="lead">
  Fresh bread and coffee,
  every morning.
</p>
<p>Prices &amp; offers &lt;today&gt;&nbsp;only</p>
<label class="field">Search the shelves
  <input type="search" placeholder="Bread, milk…" title="Search by name" aria-label="Search" />
</label>
<select aria-label="Aisle">
  <optgroup label="Food">
    <option value="bread">Bread</option>
    <option value="milk">Milk</option>
  </optgroup>
</select>
<img src="/shop.png" alt="The shop front" />
<div class="grid" aria-roledescription="shelf map"></div>
<ul>
  {#each rows as row (row)}
    <li>
      Shelf
      <span class="muted">{row}</span>
    </li>
  {/each}
</ul>
{#if open}
  <p>Open today</p>
{:else}
  <p>Closed for the day</p>
{/if}
<div>
  <p>Opening hours</p>
  Ask at the till
</div>
<button type="button">Pay now<br />or later</button>
<table>
  <thead><tr><th>Item</th><th>Price</th></tr></thead>
</table>
<p>{n} {word} waiting</p>
<p>Read the <a href="/rules">house rules</a> first.</p>
<span title="Rows: {n}">·</span>
<pre>  Receipt   text</pre>
<p translate="no">shop.example</p>
<p>{kinds[0].label}</p>
