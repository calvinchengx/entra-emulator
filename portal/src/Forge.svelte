<script>
  import { api, copy } from './api.js';

  // Token forge (roadmap #2): mint an arbitrary signed JWT without running a
  // flow — expired, wrong-audience, or bad-signature tokens for negative tests.
  let apps = $state([]);
  let users = $state([]);
  let error = $state('');
  let result = $state(null);

  let form = $state({
    tokenType: 'access',
    clientId: '',
    userId: '',
    scopes: '',
    roles: '',
    audience: '',
    expiresInSeconds: 3600,
    notBeforeSeconds: 0,
    nonce: '',
    extraClaims: '',
    signature: 'valid',
  });

  async function load() {
    try {
      apps = (await api.get('/admin/api/apps?top=200')).value ?? [];
      users = (await api.get('/admin/api/users?top=200')).value ?? [];
    } catch (e) { error = e.message; }
  }
  load();

  function words(s) {
    return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  }

  async function forge(ev) {
    ev.preventDefault();
    error = '';
    result = null;
    const body = {
      tokenType: form.tokenType,
      signature: form.signature,
      expiresInSeconds: Number(form.expiresInSeconds),
      notBeforeSeconds: Number(form.notBeforeSeconds),
    };
    if (form.clientId) body.clientId = form.clientId;
    if (form.userId) body.userId = form.userId;
    if (form.audience) body.audience = form.audience;
    if (form.nonce) body.nonce = form.nonce;
    const scp = words(form.scopes);
    if (scp.length) body.scopes = scp;
    const rls = words(form.roles);
    if (rls.length) body.roles = rls;
    if (form.extraClaims.trim()) {
      try { body.extraClaims = JSON.parse(form.extraClaims); }
      catch { error = 'extraClaims must be valid JSON.'; return; }
    }
    try { result = await api.post('/admin/api/tokens', body); }
    catch (e) { error = e.message; }
  }

  const delegated = $derived(form.userId !== '');
</script>

<h1>Token forge</h1>
<div class="banner-caution">Mints an arbitrary signed JWT with no flow — including expired, wrong-audience, and bad-signature tokens for exercising a resource API's negative paths.</div>
{#if error}<div class="banner-error">{error}</div>{/if}

<div class="grid">
  <form class="card" onsubmit={forge}>
    <label for="tt">Token type</label>
    <select id="tt" bind:value={form.tokenType}>
      <option value="access">access</option>
      <option value="id">id</option>
    </select>

    <label for="cid">Client (app)</label>
    <select id="cid" bind:value={form.clientId}>
      <option value="">— seeded SPA (default) —</option>
      {#each apps as a}<option value={a.id}>{a.displayName} · {a.id}</option>{/each}
    </select>

    <label for="uid">User</label>
    <select id="uid" bind:value={form.userId}>
      <option value="">— none (app-only token) —</option>
      {#each users as u}<option value={u.id}>{u.displayName} · {u.userPrincipalName}</option>{/each}
    </select>

    {#if form.tokenType === 'access' && delegated}
      <label for="scp">Scopes (scp) — space or comma separated</label>
      <input id="scp" bind:value={form.scopes} placeholder="User.Read Tasks.Read" />
    {/if}
    {#if form.tokenType === 'access' && !delegated}
      <label for="rls">Roles — space or comma separated</label>
      <input id="rls" bind:value={form.roles} placeholder="Tasks.Read.All" />
    {/if}
    {#if form.tokenType === 'access'}
      <label for="aud">Audience (aud) — override</label>
      <input id="aud" bind:value={form.audience} placeholder="api://… (blank = Graph)" />
    {/if}
    {#if form.tokenType === 'id'}
      <label for="nonce">Nonce</label>
      <input id="nonce" bind:value={form.nonce} />
    {/if}

    <div class="row">
      <div>
        <label for="exp">Expires in (s) — negative = already expired</label>
        <input id="exp" type="number" bind:value={form.expiresInSeconds} />
      </div>
      <div>
        <label for="nbf">Not-before offset (s)</label>
        <input id="nbf" type="number" bind:value={form.notBeforeSeconds} />
      </div>
    </div>

    <label for="extra">Extra claims (JSON, merged last — overrides anything)</label>
    <textarea id="extra" bind:value={form.extraClaims} rows="3" placeholder={'{ "ipaddr": "10.0.0.1" }'}></textarea>

    <label for="sig">Signature</label>
    <select id="sig" bind:value={form.signature}>
      <option value="valid">valid (verifies against JWKS)</option>
      <option value="invalid">invalid (fails JWKS verification)</option>
    </select>

    <div style="margin-top:16px"><button class="btn" type="submit">Forge token</button></div>
  </form>

  <div class="card">
    <h2>Result</h2>
    {#if result}
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
        <span class="muted">{result.tokenType} · kid {result.kid}</span>
        <button class="btn-secondary" style="height:28px;margin-left:auto" onclick={() => copy(result.token)}>Copy token</button>
      </div>
      <pre class="code" style="white-space:pre-wrap;word-break:break-all">{result.token}</pre>
      <h2 style="margin-top:16px;font-size:16px">Claims</h2>
      <pre class="code">{JSON.stringify(result.claims, null, 2)}</pre>
    {:else}
      <p class="muted">Fill the form and forge a token — the JWT and its decoded claims appear here.</p>
    {/if}
  </div>
</div>

<style>
  .grid { display: grid; grid-template-columns: minmax(320px, 460px) 1fr; gap: 16px; align-items: start; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  textarea { width: 100%; border: 1px solid var(--border); border-radius: 4px; padding: 6px 8px;
    font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
  textarea:focus { outline: 2px solid var(--primary); outline-offset: 1px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
</style>
