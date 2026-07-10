<script>
  import { api, copy } from './api.js';

  let { health } = $props();
  let counts = $state({ users: '—', groups: '—', apps: '—' });
  let resetMsg = $state('');

  async function load() {
    for (const kind of ['users', 'groups', 'apps']) {
      try {
        counts[kind] = (await api.get(`/admin/api/${kind}?top=1`)).count;
      } catch { /* emulator unreachable */ }
    }
  }
  load();

  const endpoints = $derived(health ? [
    ['Issuer', `${health.origins.login}/${health.tenantId}/v2.0`],
    ['Discovery', `${health.origins.login}/${health.tenantId}/v2.0/.well-known/openid-configuration`],
    ['JWKS', `${health.origins.login}/${health.tenantId}/discovery/v2.0/keys`],
    ['Authorize', `${health.origins.login}/${health.tenantId}/oauth2/v2.0/authorize`],
    ['Token', `${health.origins.login}/${health.tenantId}/oauth2/v2.0/token`],
    ['Graph', `${health.origins.graph}${health.origins.graph === health.origins.login ? '/graph' : ''}/v1.0`],
  ] : []);

  async function reset() {
    if (!confirm('Reset the directory to the deterministic seed? All non-seed data is deleted.')) return;
    await api.post('/admin/api/reset', { reseed: true });
    resetMsg = 'Directory reset to seed.';
    load();
    setTimeout(() => (resetMsg = ''), 4000);
  }
</script>

<h1>Dashboard</h1>
<div class="banner-caution">This is a local emulator with publicly known seeded credentials — not for production use.</div>
{#if resetMsg}<div class="banner-caution" style="background:var(--success-tint);color:var(--success);border-color:var(--success)">{resetMsg}</div>{/if}

<div class="tiles">
  {#each Object.entries(counts) as [k, v]}
    <div class="card tile"><div class="num">{v}</div><div class="muted" style="text-transform:uppercase;letter-spacing:.06em">{k}</div></div>
  {/each}
</div>

<div class="card" style="margin-top:16px">
  <h2>Endpoints</h2>
  <table>
    <tbody>
      {#each endpoints as [name, url]}
        <tr><td style="width:120px;font-weight:600">{name}</td>
          <td><button class="chip" onclick={() => copy(url)} title="Copy">{url}</button></td></tr>
      {/each}
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:16px">
  <h2>Maintenance</h2>
  <p class="muted">The TLS certificate PEM is at <button class="chip" onclick={() => copy('/admin/api/certificate/pem')}>/admin/api/certificate/pem</button> — download and trust it for HTTPS clients.</p>
  <a class="btn-secondary" style="display:inline-flex;align-items:center;text-decoration:none;margin-right:8px" href="/admin/api/certificate/pem" download>Download certificate</a>
  <button class="btn-danger" onclick={reset}>Reset to seed</button>
</div>

<style>
  .tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .tile { padding: 16px 20px; }
  .num { font-size: 28px; font-weight: 600; }
</style>
