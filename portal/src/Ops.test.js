import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Ops from './Ops.svelte';

describe('Operations view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.confirm = vi.fn(() => true);
    api.get.mockImplementation((path) => {
      if (path === '/health') return Promise.resolve({ origins: { login: 'https://localhost:8443' }, tenantId: 'tid' });
      if (path === '/admin/api/export') return Promise.resolve({ users: [{ id: 'u1' }], groups: [], apps: [] });
      return Promise.resolve({});
    });
    // JWKS is fetched raw (not via api) with a cache-bypass.
    globalThis.fetch = vi.fn().mockResolvedValue({
      json: () => Promise.resolve({ keys: [{ kid: 'k1', kty: 'RSA', alg: 'RS256', use: 'sig' }] }),
    });
  });

  it('derives the JWKS URL from /health and renders published keys', async () => {
    render(Ops, {});
    expect(await screen.findByText('k1')).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith('https://localhost:8443/tid/discovery/v2.0/keys', { cache: 'no-store' });
  });

  it('previews the directory export into the editor', async () => {
    render(Ops, {});
    await screen.findByText('k1');
    await fireEvent.click(screen.getByText('Load current into editor'));
    const ta = screen.getByPlaceholderText(/Paste a directory snapshot/i);
    await waitFor(() => expect(ta.value).toContain('"users"'));
  });

  it('rejects invalid JSON on import without calling the API', async () => {
    render(Ops, {});
    await screen.findByText('k1');
    const ta = screen.getByPlaceholderText(/Paste a directory snapshot/i);
    await fireEvent.input(ta, { target: { value: 'not json' } });
    await fireEvent.click(screen.getByText('Replace directory from snapshot'));
    expect(await screen.findByText('Snapshot is not valid JSON.')).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  it('rotates the signing key with the grace window', async () => {
    api.post.mockResolvedValue({ activeKid: 'k2', publishedCount: 2 });
    render(Ops, {});
    await screen.findByText('k1');
    await fireEvent.click(screen.getByText('Rotate now'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/signing-keys/rotate', { graceSeconds: 3600 });
    expect(await screen.findByText(/Rotated\. Active kid k2/i)).toBeInTheDocument();
  });
});
