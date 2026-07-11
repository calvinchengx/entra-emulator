<script>
  import { api } from './api.js';

  // SCIM provisioning client (roadmap #21b): configure a downstream SCIM
  // target, run a sync cycle, and watch the outbound request log.
  let form = $state({ endpoint: '', token: '' });
  let configured = $state(false);
  let currentEndpoint = $state('');
  let result = $state(null);
  let log = $state([]);
  let error = $state('');
  let msg = $state('');
  let auto = $state(false);
  let timer = null;

  function flash(m) { msg = m; setTimeout(() => (msg = ''), 4000); }

  async function loadTarget() {
    try {
      const t = await api.get('/admin/api/scim/target');
      configured = t.configured;
      currentEndpoint = t.endpoint ?? '';
      error = '';
    } catch (e) { error = e.message; }
  }
  async function loadLog() {
    try { log = (await api.get('/admin/api/scim/log')).value ?? []; }
    catch (e) { error = e.message; }
  }
  loadTarget();
  loadLog();

  async function saveTarget(ev) {
    ev.preventDefault();
    error = '';
    if (!form.endpoint) { error = 'Endpoint is required.'; return; }
    try {
      await api.post('/admin/api/scim/target', { endpoint: form.endpoint, token: form.token });
      flash('Target configured.');
      loadTarget();
    } catch (e) { error = e.message; }
  }

  async function clearTarget() {
    try { await api.del('/admin/api/scim/target'); configured = false; currentEndpoint = ''; flash('Target cleared.'); }
    catch (e) { error = e.message; }
  }

  async function sync(mode) {
    error = '';
    result = null;
    try {
      result = await api.post('/admin/api/scim/sync', { mode });
      flash(`${mode} sync: ${result.created} created · ${result.updated} updated · ${result.deprovisioned} deprovisioned`);
      loadLog();
    } catch (e) { error = e.message; }
  }

  function toggleAuto() {
    auto = !auto;
    if (auto) timer = setInterval(loadLog, 2000);
    else if (timer) { clearInterval(timer); timer = null; }
  }

  async function clearLog() {
    try { await api.del('/admin/api/scim/log'); log = []; }
    catch (e) { error = e.message; }
  }

  function time(t) { return t ? new Date(t * 1000).toISOString().replace('T', ' ').replace('Z', '') : ''; }
</script>

<h1>SCIM provisioning</h1>
<div class="banner-caution">Emulate Entra's <strong>outbound</strong> provisioning — push the directory to a downstream SCIM endpoint (existence probe → create / update / <code>active:false</code> deprovision), correlating group members. Configure a target, run a cycle, and watch the request log.</div>
{#if error}<div class="banner-error">{error}</div>{/if}
{#if msg}<div class="banner-caution" style="background:var(--success-tint);color:var(--success);border-color:var(--success)">{msg}</div>{/if}

<div class="card" style="margin-bottom:16px">
  <h2>Target</h2>
  {#if configured}<p class="muted">Provisioning to <span class="mono">{currentEndpoint}</span></p>{/if}
  <form onsubmit={saveTarget} style="max-width:520px">
    <label for="ep">Endpoint (base SCIM URL)</label>
    <input id="ep" bind:value={form.endpoint} placeholder="https://app.example/scim/v2" />
    <label for="tok">Bearer token</label>
    <input id="tok" type="password" bind:value={form.token} placeholder="the target's secret token" />
    <div style="margin-top:16px;display:flex;gap:8px">
      <button class="btn" type="submit">Save target</button>
      {#if configured}<button class="btn-secondary" type="button" onclick={clearTarget}>Clear target</button>{/if}
    </div>
  </form>
</div>

<div class="card" style="margin-bottom:16px">
  <h2>Run a sync</h2>
  <div style="display:flex;gap:8px;align-items:center;margin:12px 0">
    <button class="btn" onclick={() => sync('initial')} disabled={!configured}>Initial sync</button>
    <button class="btn-secondary" onclick={() => sync('incremental')} disabled={!configured}>Incremental</button>
    {#if !configured}<span class="muted">Configure a target first.</span>{/if}
  </div>
  {#if result}
    <div class="tiles">
      <div><div class="muted">Created</div><div class="big">{result.created}</div></div>
      <div><div class="muted">Updated</div><div class="big">{result.updated}</div></div>
      <div><div class="muted">Deprovisioned</div><div class="big">{result.deprovisioned}</div></div>
      <div><div class="muted">Skipped</div><div class="big">{result.skipped}</div></div>
      <div><div class="muted">Groups</div><div class="big">{result.groupsCreated + result.groupsUpdated}</div></div>
      <div><div class="muted">Failed</div><div class="big">{result.failed}</div></div>
    </div>
  {/if}
</div>

<div class="card">
  <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px">
    <h2 style="margin:0">Provisioning log</h2>
    <button class="btn-secondary" style="margin-left:auto" onclick={loadLog}>Refresh</button>
    <button class="btn-secondary" class:on={auto} onclick={toggleAuto}>{auto ? 'Auto: on' : 'Auto: off'}</button>
    <button class="btn-danger" onclick={clearLog}>Clear</button>
  </div>
  <table>
    <thead><tr><th style="width:150px">Time</th><th>Resource</th><th>Action</th><th>Subject</th><th>Request</th><th>Status</th></tr></thead>
    <tbody>
      {#each log as e}
        <tr>
          <td class="mono">{time(e.time)}</td>
          <td>{e.resource}</td>
          <td>{e.action}</td>
          <td class="mono">{e.subject}</td>
          <td class="mono">{e.method} {e.path}</td>
          <td>{#if e.status}<span class:ok={e.status < 300} class:bad={e.status >= 300}>{e.status}</span>{:else}<span class="bad" title={e.detail}>error</span>{/if}</td>
        </tr>
      {/each}
      {#if log.length === 0}
        <tr><td colspan="6" class="muted" style="text-align:center;padding:24px">No provisioning requests yet. Configure a target and run a sync.</td></tr>
      {/if}
    </tbody>
  </table>
  <div class="muted" style="margin-top:8px">{log.length} request{log.length === 1 ? '' : 's'}</div>
</div>

<style>
  .tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px; }
  .big { font-size: 20px; font-weight: 600; margin-top: 4px; }
  .mono { font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
  .ok { color: var(--success); font-weight: 600; }
  .bad { color: var(--error-ink); font-weight: 600; }
  .btn-secondary.on { background: var(--primary-tint); color: var(--primary-ink); border-color: var(--primary); }
  @media (max-width: 900px) { .tiles { grid-template-columns: repeat(3, 1fr); } }
</style>
