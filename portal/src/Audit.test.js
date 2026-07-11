import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Audit from './Audit.svelte';

const EVENTS = {
  value: [
    { timeISO: '2026-07-11T00:00:01Z', flow: 'token', grantType: 'authorization_code', clientId: 'spa', status: 200, ok: true },
    { timeISO: '2026-07-11T00:00:02Z', flow: 'token', grantType: 'client_credentials', clientId: 'daemon', status: 400, ok: false, error: 'invalid_scope', reason: 'unknown resource' },
  ],
  count: 2,
};

describe('Audit view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.confirm = vi.fn(() => true);
  });

  it('lists events with ok and error results', async () => {
    api.get.mockResolvedValue(EVENTS);
    render(Audit, {});
    expect(await screen.findByText('✓ ok')).toBeInTheDocument();
    expect(screen.getByText('✗ invalid_scope')).toBeInTheDocument();
    expect(screen.getByText('unknown resource')).toBeInTheDocument();
    expect(screen.getByText('2 events')).toBeInTheDocument();
    expect(api.get).toHaveBeenCalledWith('/admin/api/audit?limit=100');
  });

  it('renders the empty state', async () => {
    api.get.mockResolvedValue({ value: [], count: 0 });
    render(Audit, {});
    expect(await screen.findByText(/No exchanges recorded/i)).toBeInTheDocument();
  });

  it('clears the trail after confirmation', async () => {
    api.get.mockResolvedValue(EVENTS);
    api.del.mockResolvedValue(null);
    render(Audit, {});
    await screen.findByText('✓ ok');
    await fireEvent.click(screen.getByText('Clear'));
    expect(globalThis.confirm).toHaveBeenCalled();
    expect(api.del).toHaveBeenCalledWith('/admin/api/audit');
  });

  it('surfaces errors', async () => {
    api.get.mockRejectedValue(new Error('audit down'));
    render(Audit, {});
    expect(await screen.findByText('audit down')).toBeInTheDocument();
  });
});
