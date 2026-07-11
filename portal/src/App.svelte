<script>
  import Dashboard from './Dashboard.svelte';
  import Users from './Users.svelte';
  import Groups from './Groups.svelte';
  import Apps from './Apps.svelte';
  import Tenants from './Tenants.svelte';
  import Forge from './Forge.svelte';
  import Audit from './Audit.svelte';
  import Clock from './Clock.svelte';
  import Faults from './Faults.svelte';
  import Ops from './Ops.svelte';
  import Provisioning from './Provisioning.svelte';
  import Fabric from './Fabric.svelte';
  import { api } from './api.js';

  let route = $state(location.hash.slice(1) || 'dashboard');
  window.addEventListener('hashchange', () => (route = location.hash.slice(1) || 'dashboard'));

  let health = $state(null);
  api.get('/health').then((h) => (health = h)).catch(() => {});

  // Grouped navigation: directory objects, the Go-native testing tools, ops,
  // and the Fabric identity layer. Each entry is [route id, label].
  const sections = [
    ['Directory', [
      ['dashboard', 'Dashboard'],
      ['users', 'Users'],
      ['groups', 'Groups'],
      ['apps', 'App registrations'],
      ['tenants', 'Tenants'],
    ]],
    ['Testing tools', [
      ['forge', 'Token forge'],
      ['audit', 'Audit trail'],
      ['clock', 'Clock'],
      ['faults', 'Fault injection'],
    ]],
    ['Operations', [
      ['ops', 'Import / export & keys'],
      ['provisioning', 'SCIM provisioning'],
    ]],
    ['Fabric', [
      ['fabric', 'Workspace identities'],
    ]],
  ];
</script>

<div class="topbar">
  <strong>Entra Emulator</strong>
  <span class="badge">LOCAL EMULATOR</span>
  {#if health}
    <span class="chip" title="tenant">{health.tenantId}</span>
    <span class="health"><span class="dot"></span>{health.status} · v{health.version}</span>
  {/if}
</div>
<div class="shell">
  <nav class="sidenav">
    {#each sections as [title, items]}
      <div class="section-label">{title}</div>
      {#each items as [id, label]}
        <a href={'#' + id} class:active={route === id}>{label}</a>
      {/each}
    {/each}
    <div class="note muted">Not for production use.</div>
  </nav>
  <main>
    {#if route === 'users'}<Users />
    {:else if route === 'groups'}<Groups />
    {:else if route === 'apps'}<Apps {health} />
    {:else if route === 'tenants'}<Tenants {health} />
    {:else if route === 'forge'}<Forge />
    {:else if route === 'audit'}<Audit />
    {:else if route === 'clock'}<Clock />
    {:else if route === 'faults'}<Faults />
    {:else if route === 'ops'}<Ops />
    {:else if route === 'provisioning'}<Provisioning />
    {:else if route === 'fabric'}<Fabric {health} />
    {:else}<Dashboard {health} />{/if}
  </main>
</div>

<style>
  .topbar { height: 48px; background: var(--surface); border-bottom: 1px solid var(--divider);
    display: flex; align-items: center; gap: 12px; padding: 0 16px; }
  .health { margin-left: auto; color: var(--muted); font-size: 12px;
    display: flex; align-items: center; gap: 6px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #038387; display: inline-block; }
  .shell { display: flex; min-height: calc(100vh - 49px); }
  .sidenav { width: 240px; background: var(--canvas); padding: 8px; flex-shrink: 0;
    display: flex; flex-direction: column; gap: 2px; }
  .section-label { font-size: 11px; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: var(--muted); padding: 12px 12px 4px; }
  .sidenav a { display: block; padding: 8px 12px; border-radius: 4px; color: var(--ink-2);
    text-decoration: none; font-weight: 600; }
  .sidenav a:hover { background: var(--hover); }
  .sidenav a.active { background: var(--primary-tint); color: var(--primary-ink);
    border-left: 2px solid var(--primary); }
  main { flex: 1; padding: 24px; max-width: 1280px; }
  .note { margin-top: auto; padding: 12px; }
</style>
