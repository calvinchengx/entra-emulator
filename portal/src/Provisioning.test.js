import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Provisioning from './Provisioning.svelte';

// load() issues two GETs on mount: target + log.
function mockLoads(target = { configured: false, endpoint: '' }, log = []) {
  api.get.mockImplementation((path) => {
    if (path === '/admin/api/scim/target') return Promise.resolve(target);
    if (path === '/admin/api/scim/log') return Promise.resolve({ value: log });
    return Promise.resolve({});
  });
}

describe('SCIM provisioning view', () => {
  beforeEach(() => vi.clearAllMocks());

  it('shows the configured target and empty log', async () => {
    mockLoads({ configured: true, endpoint: 'https://app/scim/v2' }, []);
    render(Provisioning, {});
    expect(await screen.findByText('https://app/scim/v2')).toBeInTheDocument();
    expect(screen.getByText(/No provisioning requests yet/i)).toBeInTheDocument();
  });

  it('requires an endpoint before saving a target', async () => {
    mockLoads();
    render(Provisioning, {});
    await screen.findByText(/No provisioning requests yet/i);
    await fireEvent.click(screen.getByText('Save target'));
    expect(await screen.findByText('Endpoint is required.')).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  it('posts the target endpoint + token', async () => {
    mockLoads();
    api.post.mockResolvedValue({ configured: true, endpoint: 'https://app/scim/v2' });
    render(Provisioning, {});
    await screen.findByText(/No provisioning requests yet/i);
    await fireEvent.input(screen.getByLabelText(/Endpoint/i), { target: { value: 'https://app/scim/v2' } });
    await fireEvent.input(screen.getByLabelText(/Bearer token/i), { target: { value: 'secret' } });
    await fireEvent.click(screen.getByText('Save target'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/scim/target', {
      endpoint: 'https://app/scim/v2',
      token: 'secret',
    });
  });

  it('runs an initial sync and shows the result tiles', async () => {
    mockLoads({ configured: true, endpoint: 'https://app/scim/v2' }, []);
    api.post.mockResolvedValue({
      mode: 'initial', created: 2, updated: 0, deprovisioned: 0, skipped: 0, failed: 0,
      groupsCreated: 1, groupsUpdated: 0,
    });
    render(Provisioning, {});
    await screen.findByText('https://app/scim/v2');
    await fireEvent.click(screen.getByText('Initial sync'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/scim/sync', { mode: 'initial' });
    // "Created" tile shows 2.
    expect(await screen.findByText('Created')).toBeInTheDocument();
  });

  it('renders provisioning log rows', async () => {
    mockLoads({ configured: true, endpoint: 'https://app/scim/v2' }, [
      { time: 1_700_000_000, resource: 'User', action: 'create', subject: 'alice@x', method: 'POST', path: '/Users', status: 201 },
    ]);
    render(Provisioning, {});
    expect(await screen.findByText('alice@x')).toBeInTheDocument();
    expect(screen.getByText('201')).toBeInTheDocument();
    expect(screen.getByText('1 request')).toBeInTheDocument();
  });
});
