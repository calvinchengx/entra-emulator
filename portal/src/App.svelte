<script>
  import Dashboard from './Dashboard.svelte';
  import Users from './Users.svelte';
  import Groups from './Groups.svelte';
  import Apps from './Apps.svelte';
  import { api } from './api.js';

  let route = $state(location.hash.slice(1) || 'dashboard');
  window.addEventListener('hashchange', () => (route = location.hash.slice(1) || 'dashboard'));

  let health = $state(null);
  api.get('/health').then((h) => (health = h)).catch(() => {});

  const nav = [
    ['dashboard', 'Dashboard'],
    ['users', 'Users'],
    ['groups', 'Groups'],
    ['apps', 'App registrations'],
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
    {#each nav as [id, label]}
      <a href={'#' + id} class:active={route === id}>{label}</a>
    {/each}
    <div class="note muted">Not for production use.</div>
  </nav>
  <main>
    {#if route === 'users'}<Users />
    {:else if route === 'groups'}<Groups />
    {:else if route === 'apps'}<Apps {health} />
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
  .sidenav a { display: block; padding: 8px 12px; border-radius: 4px; color: var(--ink-2);
    text-decoration: none; font-weight: 600; }
  .sidenav a:hover { background: var(--hover); }
  .sidenav a.active { background: var(--primary-tint); color: var(--primary-ink);
    border-left: 2px solid var(--primary); }
  main { flex: 1; padding: 24px; max-width: 1280px; }
  .note { margin-top: auto; padding: 12px; }
</style>
