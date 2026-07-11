<script>
  import { api } from './api.js';

  // Fault injection (roadmap #5): make the token endpoint misbehave on demand
  // to test client failure handling the real Entra can't reproduce.
  let error = $state('');
  let saved = $state('');
  let form = $state({ tokenError: '', tokenErrorDescription: '', tokenLatencyMs: 0, probability: 1 });

  // Common OAuth errors and the HTTP status the emulator maps them to.
  const errorOptions = [
    ['', '— none (no forced error) —'],
    ['invalid_grant', 'invalid_grant → 400'],
    ['invalid_client', 'invalid_client → 401'],
    ['invalid_scope', 'invalid_scope → 400'],
    ['temporarily_unavailable', 'temporarily_unavailable → 503'],
    ['server_error', 'server_error → 500'],
    ['interaction_required', 'interaction_required → 400'],
  ];

  async function load() {
    try {
      const cfg = await api.get('/admin/api/faults');
      form = {
        tokenError: cfg.tokenError ?? '',
        tokenErrorDescription: cfg.tokenErrorDescription ?? '',
        tokenLatencyMs: cfg.tokenLatencyMs ?? 0,
        probability: cfg.probability === 0 ? 1 : (cfg.probability ?? 1),
      };
      error = '';
    } catch (e) { error = e.message; }
  }
  load();

  async function arm(ev) {
    ev.preventDefault();
    error = ''; saved = '';
    try {
      await api.post('/admin/api/faults', {
        tokenError: form.tokenError,
        tokenErrorDescription: form.tokenErrorDescription,
        tokenLatencyMs: Number(form.tokenLatencyMs),
        probability: Number(form.probability),
      });
      saved = 'Faults armed.';
      setTimeout(() => (saved = ''), 3000);
    } catch (e) { error = e.message; }
  }

  async function disarm() {
    error = ''; saved = '';
    try { await api.del('/admin/api/faults'); await load(); saved = 'All faults disarmed.'; setTimeout(() => (saved = ''), 3000); }
    catch (e) { error = e.message; }
  }

  const armed = $derived(form.tokenError !== '' || Number(form.tokenLatencyMs) > 0);
</script>

<h1>Fault injection</h1>
<div class="banner-caution">Force the <code>/token</code> endpoint to fail or stall so you can test client retry/backoff and error handling. In-memory — cleared by disarm or a restart.</div>
{#if error}<div class="banner-error">{error}</div>{/if}
{#if saved}<div class="banner-caution" style="background:var(--success-tint);color:var(--success);border-color:var(--success)">{saved}</div>{/if}

<form class="card" style="max-width:560px" onsubmit={arm}>
  <label for="err">Forced token error</label>
  <select id="err" bind:value={form.tokenError}>
    {#each errorOptions as [val, label]}<option value={val}>{label}</option>{/each}
  </select>

  <label for="desc">Error description (optional)</label>
  <input id="desc" bind:value={form.tokenErrorDescription} placeholder="AADSTS… custom message" />

  <label for="lat">Latency (ms) — delays every token response</label>
  <input id="lat" type="number" min="0" bind:value={form.tokenLatencyMs} />

  <label for="prob">Probability (0–1) — chance a set error actually fires</label>
  <input id="prob" type="number" min="0" max="1" step="0.1" bind:value={form.probability} />

  <div style="margin-top:16px;display:flex;gap:8px;align-items:center">
    <button class="btn" type="submit">Arm faults</button>
    <button class="btn-danger" type="button" onclick={disarm}>Disarm all</button>
    <span class="muted" style="margin-left:auto">{armed ? 'A fault is configured.' : 'No fault configured.'}</span>
  </div>
</form>
