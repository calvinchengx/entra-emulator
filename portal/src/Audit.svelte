<script>
  import { api } from './api.js';

  // Flow audit trail (roadmap #8): every authorize/token exchange with its
  // concrete accept/reject reason. Turns "why won't MSAL sign in" into a log.
  let events = $state([]);
  let count = $state(0);
  let limit = $state(100);
  let error = $state('');
  let auto = $state(false);
  let timer = null;

  async function load() {
    try {
      const data = await api.get(`/admin/api/audit?limit=${limit}`);
      events = data.value ?? [];
      count = data.count;
      error = '';
    } catch (e) { error = e.message; }
  }
  load();

  function toggleAuto() {
    auto = !auto;
    if (auto) { timer = setInterval(load, 2000); }
    else if (timer) { clearInterval(timer); timer = null; }
  }

  async function clear() {
    if (!confirm('Clear the audit trail?')) return;
    try { await api.del('/admin/api/audit'); load(); }
    catch (e) { error = e.message; }
  }

  function time(iso) {
    return iso ? iso.replace('T', ' ').replace('Z', '') : '';
  }
</script>

<h1>Audit trail</h1>
<div class="banner-caution">Every authorize / token exchange, newest first, with the concrete accept or reject reason (OAuth <code>error</code> + <code>error_description</code>). In-memory ring buffer (last 500).</div>
{#if error}<div class="banner-error">{error}</div>{/if}

<div class="card">
  <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px">
    <label for="lim" style="margin:0">Limit</label>
    <input id="lim" type="number" bind:value={limit} onchange={load} style="width:90px" />
    <button class="btn-secondary" onclick={load}>Refresh</button>
    <button class="btn-secondary" class:on={auto} onclick={toggleAuto}>{auto ? 'Auto: on' : 'Auto: off'}</button>
    <button class="btn-danger" style="margin-left:auto" onclick={clear}>Clear</button>
  </div>
  <table>
    <thead><tr><th style="width:150px">Time</th><th>Flow</th><th>Grant</th><th>Client</th><th>Status</th><th>Result</th></tr></thead>
    <tbody>
      {#each events as e}
        <tr>
          <td class="mono">{time(e.timeISO)}</td>
          <td>{e.flow}</td>
          <td class="mono">{e.grantType ?? ''}</td>
          <td class="mono">{e.clientId ?? ''}</td>
          <td>{e.status}</td>
          <td>
            {#if e.ok}<span class="ok">✓ ok</span>
            {:else}<span class="bad">✗ {e.error ?? 'error'}</span>{#if e.reason}<div class="muted">{e.reason}</div>{/if}{/if}
          </td>
        </tr>
      {/each}
      {#if events.length === 0}
        <tr><td colspan="6" class="muted" style="text-align:center;padding:24px">No exchanges recorded yet. Run a sign-in or token request.</td></tr>
      {/if}
    </tbody>
  </table>
  <div class="muted" style="margin-top:8px">{count} event{count === 1 ? '' : 's'}</div>
</div>

<style>
  .mono { font-family: 'Cascadia Mono', ui-monospace, monospace; font-size: 12px; }
  .ok { color: var(--success); font-weight: 600; }
  .bad { color: var(--error-ink); font-weight: 600; }
  .btn-secondary.on { background: var(--primary-tint); color: var(--primary-ink); border-color: var(--primary); }
</style>
