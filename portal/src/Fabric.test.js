import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Fabric from './Fabric.svelte';

const WI = { id: 'wi1', appId: 'app-e85e', workspaceName: 'Analytics WS', workspaceId: 'ws-f7ad', state: 'Active' };
const HEALTH = { origins: { login: 'https://localhost:8443' } };

describe('Fabric workspace-identities view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.confirm = vi.fn(() => true);
  });

  it('lists workspace identities from the API', async () => {
    api.get.mockResolvedValue({ value: [WI] });
    render(Fabric, { props: { health: HEALTH } });
    expect(await screen.findByText('Analytics WS')).toBeInTheDocument();
    expect(screen.getByText('1 identity')).toBeInTheDocument();
    expect(api.get).toHaveBeenCalledWith('/admin/api/workspace-identities');
  });

  it('renders the empty state', async () => {
    api.get.mockResolvedValue({ value: [] });
    render(Fabric, { props: { health: null } });
    expect(await screen.findByText(/No workspace identities yet/i)).toBeInTheDocument();
  });

  it('creates an identity, omitting blank fields', async () => {
    api.get.mockResolvedValue({ value: [] });
    api.post.mockResolvedValue({ id: 'new' });
    render(Fabric, { props: { health: null } });
    await screen.findByText(/No workspace identities yet/i);
    await fireEvent.click(screen.getByText('New workspace identity'));
    await fireEvent.input(screen.getByLabelText(/Workspace name/i), { target: { value: 'Sales WS' } });
    await fireEvent.click(screen.getByText('Create'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/workspace-identities', { workspaceName: 'Sales WS' });
  });

  it('changes state via the dropdown', async () => {
    api.get.mockResolvedValue({ value: [WI] });
    api.patch.mockResolvedValue(null);
    render(Fabric, { props: { health: null } });
    await screen.findByText('Analytics WS');
    await fireEvent.change(screen.getByDisplayValue('Active'), { target: { value: 'Failed' } });
    expect(api.patch).toHaveBeenCalledWith('/admin/api/workspace-identities/wi1', { state: 'Failed' });
  });

  it('mints a Fabric token via the STS endpoint and renders it', async () => {
    api.get.mockResolvedValue({ value: [WI] });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'the.fabric.jwt',
        resource: 'https://api.fabric.microsoft.com',
        client_id: 'app-e85e',
        expires_in: 3600,
      }),
    });
    render(Fabric, { props: { health: HEALTH } });
    await screen.findByText('Analytics WS');
    await fireEvent.click(screen.getByText('Get token'));
    expect(fetch).toHaveBeenCalledWith('https://localhost:8443/fabric/workspaceidentities/wi1/token');
    expect(await screen.findByText('the.fabric.jwt')).toBeInTheDocument();
  });

  it('deletes after confirmation', async () => {
    api.get.mockResolvedValue({ value: [WI] });
    api.del.mockResolvedValue(null);
    render(Fabric, { props: { health: null } });
    await screen.findByText('Analytics WS');
    await fireEvent.click(screen.getByText('Delete'));
    expect(globalThis.confirm).toHaveBeenCalled();
    expect(api.del).toHaveBeenCalledWith('/admin/api/workspace-identities/wi1');
  });
});
