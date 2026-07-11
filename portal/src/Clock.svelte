<script>
  import { api } from './api.js';

  // Clock control (roadmap #6): offset / advance / freeze / reset the emulator
  // clock so token-expiry and refresh logic are testable without real sleeps.
  let state = $state(null);
  let error = $state('');
  let advanceBy = $state(3600);

  async function load() {
    try { state = await api.get('/admin/api/clock'); error = ''; }
    catch (e) { error = e.message; }
  }
  load();

  async function apply(body) {
    error = '';
    try { state = await api.post('/admin/api/clock', body); }
    catch (e) { error = e.message; }
  }

  async function reset() {
    error = '';
    try { await api.del('/admin/api/clock'); load(); }
    catch (e) { error = e.message; }
  }

  const presets = [
    ['+1 min', 60], ['+1 hour', 3600], ['+1 day', 86400], ['+31 days', 2678400],
  ];
</script>

<h1>Clock</h1>
<div class="banner-caution">Advance or freeze the emulator clock — every timestamp it stamps (token <code>iat</code>/<code>exp</code>, refresh & device-code expiry, sessions) flows through this. Advance past a token's lifetime to expire it with no real sleep. In-memory; reset restores real time.</div>
{#if error}<div class="banner-error">{error}</div>{/if}

{#if state}
  <div class="card" style="margin-bottom:16px">
    <div class="tiles">
      <div><div class="muted">Emulator now</div><div class="big mono">{state.nowISO}</div></div>
      <div><div class="muted">Offset from real</div><div class="big mono">{state.offsetSeconds}s</div></div>
      <div><div class="muted">Frozen</div><div class="big">{state.frozen ? 'yes' : 'no'}</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Advance time</h2>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      {#each presets as [label, secs]}
        <button class="btn-secondary" onclick={() => apply({ advanceSeconds: secs })}>{label}</button>
      {/each}
    </div>
    <div style="display:flex;gap:8px;align-items:flex-end;max-width:420px">
      <div style="flex:1"><label for="adv">Advance by (seconds)</label>
        <input id="adv" type="number" bind:value={advanceBy} /></div>
      <button class="btn" onclick={() => apply({ advanceSeconds: Number(advanceBy) })}>Advance</button>
    </div>

    <h2 style="margin-top:24px">Freeze / reset</h2>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      {#if state.frozen}
        <button class="btn-secondary" onclick={() => apply({ frozen: false })}>Unfreeze (resume, no jump)</button>
      {:else}
        <button class="btn-secondary" onclick={() => apply({ frozen: true })}>Freeze</button>
      {/if}
      <button class="btn-secondary" onclick={() => apply({ offsetSeconds: 0 })}>Zero offset</button>
      <button class="btn-danger" onclick={reset}>Reset to real time</button>
    </div>
  </div>
{/if}

<style>
  .tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .big { font-size: 20px; font-weight: 600; margin-top: 4px; }
  .mono { font-family: 'Cascadia Mono', ui-monospace, monospace; }
</style>
