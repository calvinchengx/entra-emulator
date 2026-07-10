<script>
  import { api, copy } from './api.js';

  let { health } = $props();
  let apps = $state([]);
  let error = $state('');
  let showCreate = $state(false);
  let form = $state({ displayName: '', isConfidential: false, redirectUri: '' });
  let expanded = $state(null);
  let detail = $state(null);
  let newSecret = $state(null); // show-once dialog payload
  let newRedirect = $state('');
  let snippetApp = $state(null);

  async function load() {
    try { apps = (await api.get('/admin/api/apps?top=200')).value ?? []; error = ''; }
    catch (e) { error = e.message; }
  }
  load();

  async function create(ev) {
    ev.preventDefault();
    try {
      const body = { displayName: form.displayName, isConfidential: form.isConfidential };
      if (form.redirectUri) body.redirectUris = [{ uri: form.redirectUri, type: form.isConfidential ? 'web' : 'spa' }];
      await api.post('/admin/api/apps', body);
      form = { displayName: '', isConfidential: false, redirectUri: '' };
      showCreate = false;
      load();
    } catch (e) { error = e.message; }
  }

  async function toggle(a) {
    if (expanded === a.id) { expanded = null; detail = null; return; }
    expanded = a.id;
    detail = await api.get(`/admin/api/apps/${a.id}`);
  }

  async function refreshDetail() {
    detail = await api.get(`/admin/api/apps/${expanded}`);
    load();
  }

  async function addSecret() {
    try { newSecret = await api.post(`/admin/api/apps/${expanded}/secrets`, { displayName: 'portal-created' }); refreshDetail(); }
    catch (e) { error = e.message; }
  }

  async function addRedirect() {
    if (!newRedirect) return;
    try { await api.post(`/admin/api/apps/${expanded}/redirectUris`, { uri: newRedirect }); newRedirect = ''; refreshDetail(); }
    catch (e) { error = e.message; }
  }

  async function remove(a) {
    if (!confirm(`Delete app ${a.displayName}? Its secrets, scopes, and roles are removed.`)) return;
    try { await api.del(`/admin/api/apps/${a.id}`); expanded = null; load(); }
    catch (e) { error = e.message; }
  }

  function msalSnippet(a) {
    const login = health?.origins?.login ?? 'https://localhost:8443';
    const u = new URL(login);
    const redirect = a.redirectUris?.[0]?.uri ?? 'https://localhost:3000';
    return JSON.stringify({
      auth: {
        clientId: a.id,
        authority: `${login}/${health?.tenantId ?? ''}`,
        knownAuthorities: [u.host],
        redirectUri: redirect,
      },
    }, null, 2);
  }
</script>

<h1>App registrations</h1>
{#if error}<div class="banner-error">{error}</div>{/if}

{#if newSecret}
  <div class="card" style="border:2px solid var(--caution);margin-bottom:16px">
    <div class="banner-caution">Copy this secret now — it is shown only once and cannot be retrieved later.</div>
    <div style="display:flex;gap:8px;align-items:center">
      <input readonly value={newSecret.secretText} style="font-family:'Cascadia Mono',monospace" />
      <button class="btn" onclick={() => copy(newSecret.secretText)}>Copy</button>
      <button class="btn-secondary" onclick={() => (newSecret = null)}>Close</button>
    </div>
    <div class="muted" style="margin-top:8px">hint {newSecret.hint} · id {newSecret.id}</div>
  </div>
{/if}

<div class="card">
  <div style="display:flex;margin-bottom:12px">
    <button class="btn" style="margin-left:auto" onclick={() => (showCreate = !showCreate)}>New app</button>
  </div>
  {#if showCreate}
    <form onsubmit={create} style="border:1px solid var(--divider);border-radius:4px;padding:16px;margin-bottom:16px;max-width:480px">
      <label for="an">Display name</label>
      <input id="an" bind:value={form.displayName} required />
      <label for="ru">Redirect URI (optional)</label>
      <input id="ru" bind:value={form.redirectUri} placeholder="https://localhost:3000" />
      <label style="display:flex;align-items:center;gap:8px;font-weight:400">
        <input type="checkbox" bind:checked={form.isConfidential} style="width:auto;height:auto" />
        Confidential client (web app / daemon — uses a client secret)
      </label>
      <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn" type="submit">Create</button>
        <button class="btn-secondary" type="button" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </form>
  {/if}
  <table>
    <thead><tr><th>Name</th><th>Client ID</th><th>Type</th><th></th><th></th></tr></thead>
    <tbody>
      {#each apps as a}
        <tr>
          <td>{a.displayName}</td>
          <td><button class="chip" onclick={() => copy(a.id)}>{a.id}</button></td>
          <td>{a.isConfidential ? 'Confidential' : 'Public (SPA)'}</td>
          <td><button class="btn-secondary" style="height:24px;padding:0 10px" onclick={() => toggle(a)}>{expanded === a.id ? 'Hide' : 'Manage'}</button>
            <button class="btn-secondary" style="height:24px;padding:0 10px" onclick={() => (snippetApp = snippetApp?.id === a.id ? null : a)}>MSAL config</button></td>
          <td style="text-align:right"><button class="btn-danger" onclick={() => remove(a)}>Delete</button></td>
        </tr>
        {#if snippetApp?.id === a.id}
          <tr><td colspan="5" style="background:var(--canvas)">
            <pre class="code">{msalSnippet(a)}</pre>
            <button class="btn-secondary" onclick={() => copy(msalSnippet(a))}>Copy snippet</button>
          </td></tr>
        {/if}
        {#if expanded === a.id && detail}
          <tr><td colspan="5" style="background:var(--canvas)">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
              <div>
                <h2 style="font-size:16px">Redirect URIs</h2>
                {#each detail.redirectUris as ru}
                  <div style="margin:4px 0"><span class="chip">{ru.uri}</span> <span class="muted">{ru.type}</span></div>
                {/each}
                <div style="display:flex;gap:4px;margin-top:8px;max-width:420px">
                  <input placeholder="https://localhost:5173" bind:value={newRedirect} style="height:28px" />
                  <button class="btn-secondary" style="height:28px" onclick={addRedirect}>Add</button>
                </div>
                <h2 style="font-size:16px;margin-top:16px">Exposed scopes</h2>
                {#each detail.exposedScopes as sc}<div><span class="chip">{sc.value}</span></div>{:else}<div class="muted">none</div>{/each}
                <h2 style="font-size:16px;margin-top:16px">App roles</h2>
                {#each detail.appRoles as ro}<div><span class="chip">{ro.value}</span></div>{:else}<div class="muted">none</div>{/each}
              </div>
              <div>
                <h2 style="font-size:16px">Secrets</h2>
                {#each detail.secrets as sec}
                  <div style="margin:4px 0"><span class="chip">••••{sec.hint}</span>
                    <span class="muted">{sec.displayName ?? ''}</span>
                    <button class="btn-danger" style="height:20px;padding:0 6px"
                      onclick={async () => { await api.del(`/admin/api/apps/${a.id}/secrets/${sec.id}`); refreshDetail(); }}>×</button></div>
                {:else}<div class="muted">none</div>{/each}
                <button class="btn-secondary" style="margin-top:8px;height:28px" onclick={addSecret}>New secret</button>
                {#if detail.appIdUri}
                  <h2 style="font-size:16px;margin-top:16px">Application ID URI</h2>
                  <span class="chip">{detail.appIdUri}</span>
                {/if}
              </div>
            </div>
          </td></tr>
        {/if}
      {/each}
    </tbody>
  </table>
</div>
