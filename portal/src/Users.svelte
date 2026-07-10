<script>
  import { api, copy } from './api.js';

  let users = $state([]);
  let count = $state(0);
  let search = $state('');
  let error = $state('');
  let showCreate = $state(false);
  let form = $state({ userPrincipalName: '', displayName: '', mail: '', password: '' });

  async function load() {
    try {
      const page = await api.get(`/admin/api/users?top=200&search=${encodeURIComponent(search)}`);
      users = page.value ?? [];
      count = page.count;
      error = '';
    } catch (e) { error = e.message; }
  }
  load();

  async function create(ev) {
    ev.preventDefault();
    try {
      const body = { userPrincipalName: form.userPrincipalName, displayName: form.displayName };
      if (form.mail) body.mail = form.mail;
      if (form.password) body.password = form.password;
      await api.post('/admin/api/users', body);
      form = { userPrincipalName: '', displayName: '', mail: '', password: '' };
      showCreate = false;
      load();
    } catch (e) { error = e.message; }
  }

  async function toggleEnabled(u) {
    try { await api.patch(`/admin/api/users/${u.id}`, { accountEnabled: !u.accountEnabled }); load(); }
    catch (e) { error = e.message; }
  }

  async function remove(u) {
    if (!confirm(`Delete ${u.userPrincipalName}?`)) return;
    try { await api.del(`/admin/api/users/${u.id}`); load(); }
    catch (e) { error = e.message; }
  }
</script>

<h1>Users</h1>
{#if error}<div class="banner-error">{error}</div>{/if}
<div class="card">
  <div style="display:flex;gap:12px;margin-bottom:12px">
    <input placeholder="Search users…" bind:value={search} oninput={load} style="max-width:280px" />
    <button class="btn" style="margin-left:auto" onclick={() => (showCreate = !showCreate)}>New user</button>
  </div>
  {#if showCreate}
    <form onsubmit={create} style="border:1px solid var(--divider);border-radius:4px;padding:16px;margin-bottom:16px;max-width:480px">
      <label for="upn">User principal name</label>
      <input id="upn" bind:value={form.userPrincipalName} placeholder="carol@entralocal.dev" required />
      <label for="dn">Display name</label>
      <input id="dn" bind:value={form.displayName} placeholder="Carol Example" required />
      <label for="mail">Mail (optional)</label>
      <input id="mail" bind:value={form.mail} type="email" />
      <label for="pw">Password (optional — enables REQUIRE_PASSWORD sign-in)</label>
      <input id="pw" bind:value={form.password} type="text" autocomplete="off" />
      <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn" type="submit">Create</button>
        <button class="btn-secondary" type="button" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </form>
  {/if}
  <table>
    <thead><tr><th>Display name</th><th>UPN</th><th>Object ID</th><th>Password</th><th>Enabled</th><th></th></tr></thead>
    <tbody>
      {#each users as u}
        <tr>
          <td>{u.displayName}</td>
          <td>{u.userPrincipalName}</td>
          <td><button class="chip" onclick={() => copy(u.id)} title="Copy">{u.id}</button></td>
          <td>{u.hasPassword ? 'set' : '—'}</td>
          <td><button class="btn-secondary" style="height:24px;padding:0 10px" onclick={() => toggleEnabled(u)}>{u.accountEnabled ? 'Yes' : 'No'}</button></td>
          <td style="text-align:right"><button class="btn-danger" onclick={() => remove(u)}>Delete</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
  <div class="muted" style="margin-top:8px">{count} user{count === 1 ? '' : 's'}</div>
</div>
