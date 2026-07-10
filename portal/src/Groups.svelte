<script>
  import { api, copy } from './api.js';

  let groups = $state([]);
  let users = $state([]);
  let error = $state('');
  let newName = $state('');
  let expanded = $state(null); // group id whose members are shown
  let members = $state([]);
  let addUserId = $state('');

  async function load() {
    try {
      groups = (await api.get('/admin/api/groups?top=200')).value ?? [];
      users = (await api.get('/admin/api/users?top=200')).value ?? [];
      error = '';
    } catch (e) { error = e.message; }
  }
  load();

  async function create(ev) {
    ev.preventDefault();
    try {
      await api.post('/admin/api/groups', { displayName: newName });
      newName = '';
      load();
    } catch (e) { error = e.message; }
  }

  async function toggleMembers(g) {
    if (expanded === g.id) { expanded = null; return; }
    expanded = g.id;
    members = (await api.get(`/admin/api/groups/${g.id}/members`)).value ?? [];
  }

  async function addMember(g) {
    if (!addUserId) return;
    try {
      await api.post(`/admin/api/groups/${g.id}/members`, { userId: addUserId });
      members = (await api.get(`/admin/api/groups/${g.id}/members`)).value ?? [];
      load();
    } catch (e) { error = e.message; }
  }

  async function removeMember(g, u) {
    await api.del(`/admin/api/groups/${g.id}/members/${u.id}`);
    members = (await api.get(`/admin/api/groups/${g.id}/members`)).value ?? [];
    load();
  }

  async function remove(g) {
    if (!confirm(`Delete group ${g.displayName}?`)) return;
    try { await api.del(`/admin/api/groups/${g.id}`); expanded = null; load(); }
    catch (e) { error = e.message; }
  }
</script>

<h1>Groups</h1>
{#if error}<div class="banner-error">{error}</div>{/if}
<div class="card">
  <form onsubmit={create} style="display:flex;gap:8px;margin-bottom:12px;max-width:480px">
    <input placeholder="New group name…" bind:value={newName} required />
    <button class="btn" type="submit">Create</button>
  </form>
  <table>
    <thead><tr><th>Name</th><th>ID</th><th>Members</th><th></th></tr></thead>
    <tbody>
      {#each groups as g}
        <tr>
          <td>{g.displayName}</td>
          <td><button class="chip" onclick={() => copy(g.id)}>{g.id}</button></td>
          <td><button class="btn-secondary" style="height:24px;padding:0 10px" onclick={() => toggleMembers(g)}>{g.memberCount} member{g.memberCount === 1 ? '' : 's'}</button></td>
          <td style="text-align:right"><button class="btn-danger" onclick={() => remove(g)}>Delete</button></td>
        </tr>
        {#if expanded === g.id}
          <tr><td colspan="4" style="background:var(--canvas)">
            {#each members as m}
              <span style="display:inline-flex;align-items:center;gap:4px;margin:2px 8px 2px 0">
                {m.displayName} <button class="btn-danger" style="height:20px;padding:0 6px" onclick={() => removeMember(g, m)}>×</button>
              </span>
            {/each}
            <span style="display:inline-flex;gap:4px;margin-left:8px">
              <select bind:value={addUserId} style="width:220px;height:28px">
                <option value="">Add member…</option>
                {#each users as u}<option value={u.id}>{u.userPrincipalName}</option>{/each}
              </select>
              <button class="btn-secondary" style="height:28px" onclick={() => addMember(g)}>Add</button>
            </span>
          </td></tr>
        {/if}
      {/each}
    </tbody>
  </table>
</div>
