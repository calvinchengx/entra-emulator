import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Forge from './Forge.svelte';

// Render with empty app/user lists (load() issues two GETs).
async function mount() {
  api.get.mockResolvedValue({ value: [] });
  render(Forge, {});
  // Wait for the form to be present.
  await screen.findByText('Forge token');
}

describe('Token forge view', () => {
  beforeEach(() => vi.clearAllMocks());

  it('forges an app-only token with defaults, omitting blank fields', async () => {
    await mount();
    api.post.mockResolvedValue({ token: 'jwt', tokenType: 'access', kid: 'k1', claims: {} });

    await fireEvent.click(screen.getByText('Forge token'));

    expect(api.post).toHaveBeenCalledTimes(1);
    const [path, body] = api.post.mock.calls[0];
    expect(path).toBe('/admin/api/tokens');
    // Only the always-present fields; no clientId/userId/audience/scopes/roles.
    expect(body).toEqual({
      tokenType: 'access',
      signature: 'valid',
      expiresInSeconds: 3600,
      notBeforeSeconds: 0,
    });
  });

  it('splits roles on spaces/commas and coerces a negative expiry', async () => {
    await mount();
    api.post.mockResolvedValue({ token: 'jwt', tokenType: 'access', kid: 'k1', claims: {} });

    await fireEvent.input(screen.getByLabelText(/Roles/i), { target: { value: 'Tasks.Read.All, Files.Read' } });
    await fireEvent.input(screen.getByLabelText(/Expires in/i), { target: { value: '-300' } });
    await fireEvent.click(screen.getByText('Forge token'));

    const body = api.post.mock.calls[0][1];
    expect(body.roles).toEqual(['Tasks.Read.All', 'Files.Read']);
    expect(body.expiresInSeconds).toBe(-300);
  });

  it('rejects invalid extraClaims JSON without calling the API', async () => {
    await mount();
    await fireEvent.input(screen.getByLabelText(/Extra claims/i), { target: { value: 'not json' } });
    await fireEvent.click(screen.getByText('Forge token'));

    expect(api.post).not.toHaveBeenCalled();
    expect(await screen.findByText('extraClaims must be valid JSON.')).toBeInTheDocument();
  });

  it('parses valid extraClaims into the body and shows the result', async () => {
    await mount();
    api.post.mockResolvedValue({ token: 'the.jwt.token', tokenType: 'access', kid: 'kid9', claims: { ipaddr: '10.0.0.1' } });

    await fireEvent.input(screen.getByLabelText(/Extra claims/i), { target: { value: '{ "ipaddr": "10.0.0.1" }' } });
    await fireEvent.click(screen.getByText('Forge token'));

    expect(api.post.mock.calls[0][1].extraClaims).toEqual({ ipaddr: '10.0.0.1' });
    // Result panel renders the returned token.
    expect(await screen.findByText('the.jwt.token')).toBeInTheDocument();
  });
});
