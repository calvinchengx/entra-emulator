<script>
  import { api, copy } from './api.js';

  // Multi-tenant directories (roadmap #15b). Each tenant has its own tid,
  // GUID-form issuer, and signing key. The home tenant cannot be deleted.
  let { health } = $props();
  let tenants = $state([]);
  let error = $state('');
  let showCreate = $state(false);
  let form = $state({ displayName: '', initialDomain: '' });

  async function load() {
    try { tenants = (await api.get('/admin/api/tenants')).value ?? []; error = ''; }
    catch (e) { error = e.message; }
  }
  load();

  async function create(ev) {
    ev.preventDefault();
    error = '';
    const body = {};
    if (form.displayName) body.displayName = form.displayName;
    if (form.initialDomain) body.initialDomain = form.initialDomain;
    try {
      await api.post('/admin/api/tenants', body);
      form = { displayName: '', initialDomain: '' };
      showCreate = false;
      load();
    } catch (e) { error = e.message; }
  }

  async function remove(t) {
    if (!confirm(`Delete tenant ${t.displayName}? Its apps and signing key are removed.`)) return;
    try { await api.del(`/admin/api/tenants/${t.id}`); load(); }
    catch (e) { error = e.message; }
  }
</script>

<h1>Tenants</h1>
<div class="banner-caution">Each tenant carries its own <code>tid</code>, GUID-form issuer, and RS256 signing key. The <code>{'{tenant}'}</code> path segment resolves the home GUID (and <code>common</code>/<code>organizations</code>/<code>consumers</code> aliases) to home; any other known GUID routes to that tenant.</div>
{#if error}<div class="banner-error">{error}</div>{/if}

<div class="card">
  <div style="display:flex;margin-bottom:12px">
    <button class="btn" style="margin-left:auto" onclick={() => (showCreate = !showCreate)}>New tenant</button>
  </div>
  {#if showCreate}
    <form onsubmit={create} style="border:1px solid var(--divider);border-radius:4px;padding:16px;margin-bottom:16px;max-width:480px">
      <label for="dn">Display name (optional — generated if blank)</label>
      <input id="dn" bind:value={form.displayName} placeholder="Contoso Ltd" />
      <label for="dom">Initial domain (optional — &lt;slug&gt;.onmicrosoft.com if blank)</label>
      <input id="dom" bind:value={form.initialDomain} placeholder="contoso.onmicrosoft.com" />
      <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn" type="submit">Create</button>
        <button class="btn-secondary" type="button" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </form>
  {/if}
  <table>
    <thead><tr><th>Display name</th><th>Tenant ID</th><th>Initial domain</th><th>Issuer</th><th></th></tr></thead>
    <tbody>
      {#each tenants as t}
        <tr>
          <td>{t.displayName}{#if t.isHome}<span class="home">home</span>{/if}</td>
          <td><button class="chip" onclick={() => copy(t.id)} title="Copy">{t.id}</button></td>
          <td>{t.initialDomain ?? '—'}</td>
          <td><button class="chip" onclick={() => copy(t.issuer)} title="Copy">{t.issuer}</button></td>
          <td style="text-align:right">
            {#if !t.isHome}<button class="btn-danger" onclick={() => remove(t)}>Delete</button>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <div class="muted" style="margin-top:8px">{tenants.length} tenant{tenants.length === 1 ? '' : 's'}</div>
</div>

<style>
  .home { background: var(--primary-tint); color: var(--primary-ink); font-size: 11px;
    font-weight: 600; border-radius: 4px; padding: 1px 6px; margin-left: 8px; }
</style>
