<script>
  import { api, copy } from './api.js';

  // Fabric workspace identities (roadmap #16b). An auto-managed service
  // principal linked to a Fabric workspace; the platform holds the credential
  // and mints tokens internally — the caller supplies only the identity id.
  let { health } = $props();
  let items = $state([]);
  let error = $state('');
  let showCreate = $state(false);
  let form = $state({ workspaceName: '', workspaceId: '' });
  let token = $state(null); // { id, resp }

  const states = ['Active', 'Provisioning', 'Failed', 'Deprovisioning'];

  async function load() {
    try { items = (await api.get('/admin/api/workspace-identities')).value ?? []; error = ''; }
    catch (e) { error = e.message; }
  }
  load();

  async function create(ev) {
    ev.preventDefault();
    error = '';
    const body = {};
    if (form.workspaceName) body.workspaceName = form.workspaceName;
    if (form.workspaceId) body.workspaceId = form.workspaceId;
    try {
      await api.post('/admin/api/workspace-identities', body);
      form = { workspaceName: '', workspaceId: '' };
      showCreate = false;
      load();
    } catch (e) { error = e.message; }
  }

  async function setState(wi, state) {
    error = '';
    try { await api.patch(`/admin/api/workspace-identities/${wi.id}`, { state }); load(); }
    catch (e) { error = e.message; }
  }

  async function remove(wi) {
    if (!confirm(`Delete workspace identity for ${wi.workspaceName}? The service principal is cascaded.`)) return;
    try { await api.del(`/admin/api/workspace-identities/${wi.id}`); load(); }
    catch (e) { error = e.message; }
  }

  async function getToken(wi) {
    error = ''; token = null;
    const base = health ? health.origins.login : '';
    try {
      const resp = await fetch(`${base}/fabric/workspaceidentities/${wi.id}/token`);
      const data = await resp.json();
      if (!resp.ok) { error = data.error_description || data.error || `HTTP ${resp.status}`; return; }
      token = { id: wi.id, resp: data };
    } catch (e) { error = e.message; }
  }
</script>

<h1>Workspace identities</h1>
<div class="banner-caution">Entra token layer only — the emulator issues the tokens a Microsoft Fabric environment relies on. Tokens are minted internally (like managed identity), so <code>Active</code> identities acquire a Fabric-audience token with no caller-held credential. The Fabric control plane itself is out of scope.</div>
{#if error}<div class="banner-error">{error}</div>{/if}

<div class="card">
  <div style="display:flex;margin-bottom:12px">
    <button class="btn" style="margin-left:auto" onclick={() => (showCreate = !showCreate)}>New workspace identity</button>
  </div>
  {#if showCreate}
    <form onsubmit={create} style="border:1px solid var(--divider);border-radius:4px;padding:16px;margin-bottom:16px;max-width:480px">
      <label for="wn">Workspace name (optional — generated if blank)</label>
      <input id="wn" bind:value={form.workspaceName} placeholder="Sales Analytics" />
      <label for="wid">Workspace ID (optional — GUID generated if blank)</label>
      <input id="wid" bind:value={form.workspaceId} placeholder="(GUID)" />
      <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn" type="submit">Create</button>
        <button class="btn-secondary" type="button" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </form>
  {/if}
  <table>
    <thead><tr><th>Workspace</th><th>App ID</th><th>State</th><th>Token</th><th></th></tr></thead>
    <tbody>
      {#each items as wi}
        <tr>
          <td>{wi.workspaceName}<div class="muted mono">{wi.workspaceId}</div></td>
          <td><button class="chip" onclick={() => copy(wi.appId)} title="Copy">{wi.appId}</button></td>
          <td>
            <select value={wi.state} onchange={(e) => setState(wi, e.target.value)} style="width:150px;height:28px">
              {#each states as s}<option value={s}>{s}</option>{/each}
            </select>
          </td>
          <td><button class="btn-secondary" style="height:28px" onclick={() => getToken(wi)} disabled={wi.state !== 'Active'}>Get token</button></td>
          <td style="text-align:right"><button class="btn-danger" onclick={() => remove(wi)}>Delete</button></td>
        </tr>
        {#if token && token.id === wi.id}
          <tr><td colspan="5">
            <div class="muted" style="margin-bottom:4px">aud <span class="mono">{token.resp.resource}</span> · client_id <span class="mono">{token.resp.client_id}</span> · expires_in {token.resp.expires_in}s
              <button class="btn-secondary" style="height:24px;margin-left:8px" onclick={() => copy(token.resp.access_token)}>Copy</button></div>
            <pre class="code" style="white-space:pre-wrap;word-break:break-all">{token.resp.access_token}</pre>
          </td></tr>
        {/if}
      {/each}
      {#if items.length === 0}
        <tr><td colspan="5" class="muted" style="text-align:center;padding:24px">No workspace identities yet.</td></tr>
      {/if}
    </tbody>
  </table>
  <div class="muted" style="margin-top:8px">{items.length} identit{items.length === 1 ? 'y' : 'ies'}</div>
</div>

<style>
  .mono { font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
</style>
