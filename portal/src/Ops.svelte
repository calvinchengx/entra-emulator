<script>
  import { api } from './api.js';

  // Operations: directory import/export (roadmap #7) and signing-key rotation
  // (roadmap #14).
  let error = $state('');
  let msg = $state('');
  let importText = $state('');
  let grace = $state(3600);
  let rotateResult = $state(null);
  let jwks = $state([]);

  function flash(m) { msg = m; setTimeout(() => (msg = ''), 4000); }

  async function loadJwks() {
    try {
      const h = await api.get('/health');
      const url = `${h.origins.login}/${h.tenantId}/discovery/v2.0/keys`;
      // JWKS is served with a long max-age; bypass the HTTP cache so a rotation
      // is reflected immediately in this admin view.
      const resp = await fetch(url, { cache: 'no-store' });
      const data = await resp.json();
      jwks = data.keys ?? [];
    } catch { jwks = []; }
  }
  loadJwks();

  async function preview() {
    error = '';
    try {
      const snap = await api.get('/admin/api/export');
      importText = JSON.stringify(snap, null, 2);
      flash('Loaded current directory into the editor below.');
    } catch (e) { error = e.message; }
  }

  async function onFile(ev) {
    const file = ev.target.files?.[0];
    if (!file) return;
    importText = await file.text();
    flash(`Loaded ${file.name} (${file.size} bytes).`);
  }

  async function runImport() {
    error = '';
    if (!importText.trim()) { error = 'Nothing to import — paste or load a snapshot first.'; return; }
    if (!confirm('Replace the entire directory with this snapshot? Current users, groups, and apps are overwritten.')) return;
    let snap;
    try { snap = JSON.parse(importText); }
    catch { error = 'Snapshot is not valid JSON.'; return; }
    try {
      const r = await api.post('/admin/api/import', snap);
      flash(`Imported ${r.imported.users} users, ${r.imported.groups} groups, ${r.imported.apps} apps.`);
    } catch (e) { error = e.message; }
  }

  async function rotate() {
    error = ''; rotateResult = null;
    try {
      rotateResult = await api.post('/admin/api/signing-keys/rotate', { graceSeconds: Number(grace) });
      flash(`Rotated. Active kid ${rotateResult.activeKid}; ${rotateResult.publishedCount} key(s) in JWKS.`);
      loadJwks();
    } catch (e) { error = e.message; }
  }
</script>

<h1>Import / export &amp; keys</h1>
{#if error}<div class="banner-error">{error}</div>{/if}
{#if msg}<div class="banner-caution" style="background:var(--success-tint);color:var(--success);border-color:var(--success)">{msg}</div>{/if}

<div class="card" style="margin-bottom:16px">
  <h2>Directory export / import</h2>
  <p class="muted">Dump the directory (users, groups + memberships, apps + sub-resources) as a portable JSON fixture, or replace it from one. Password &amp; secret hashes are included, so a round-trip preserves authentication. Signing keys and live grants are excluded.</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin:12px 0">
    <a class="btn-secondary" style="display:inline-flex;align-items:center;text-decoration:none" href="/admin/api/export" download>Download snapshot</a>
    <button class="btn-secondary" onclick={preview}>Load current into editor</button>
    <label class="btn-secondary" style="display:inline-flex;align-items:center;margin:0;font-weight:600" for="file">Choose file…
      <input id="file" type="file" accept="application/json,.json" onchange={onFile} style="display:none" /></label>
  </div>
  <textarea bind:value={importText} rows="12" placeholder="Paste a directory snapshot here, or load one with the buttons above…"></textarea>
  <div style="margin-top:12px"><button class="btn-danger" onclick={runImport}>Replace directory from snapshot</button></div>
</div>

<div class="card">
  <h2>Signing-key rotation</h2>
  <p class="muted">Generate a new active signing key and retire the current one. The retired key keeps publishing in JWKS for the grace window, so tokens already issued still verify. <code>graceSeconds: 0</code> drops it immediately.</p>
  <div style="display:flex;gap:8px;align-items:flex-end;max-width:420px;margin:12px 0">
    <div style="flex:1"><label for="grace">Grace (seconds)</label>
      <input id="grace" type="number" min="0" bind:value={grace} /></div>
    <button class="btn" onclick={rotate}>Rotate now</button>
  </div>
  <h2 style="font-size:16px;margin-top:16px">Published keys (JWKS)</h2>
  {#if jwks.length}
    <table>
      <thead><tr><th>kid</th><th>kty</th><th>alg</th><th>use</th></tr></thead>
      <tbody>
        {#each jwks as k}
          <tr><td class="mono">{k.kid}</td><td>{k.kty}</td><td>{k.alg ?? ''}</td><td>{k.use ?? ''}</td></tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="muted">JWKS unavailable.</p>
  {/if}
</div>

<style>
  textarea { width: 100%; border: 1px solid var(--border); border-radius: 4px; padding: 8px;
    font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
  textarea:focus { outline: 2px solid var(--primary); outline-offset: 1px; }
  .mono { font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
</style>
