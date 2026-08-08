import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

// Mock the shared API client; each test drives its return values.
vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Tenants from './Tenants.svelte';

const HOME = {
  id: '6f89cf12-978b-4d23-ac18-9ef0c127cf87',
  displayName: 'Home Tenant',
  initialDomain: 'home.onmicrosoft.com',
  issuer: 'https://localhost/6f89cf12-978b-4d23-ac18-9ef0c127cf87/v2.0',
  isHome: true,
};
const B = {
  id: 'e3e29cf2-136c-4e1d-90a0-bcc014db0edc',
  displayName: 'Contoso',
  initialDomain: 'contoso.onmicrosoft.com',
  issuer: 'https://localhost/e3e29cf2-136c-4e1d-90a0-bcc014db0edc/v2.0',
  isHome: false,
};

describe('Tenants view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.confirm = vi.fn(() => true);
  });

  it('lists tenants from the API and flags the home tenant', async () => {
    api.get.mockResolvedValue({ value: [HOME, B] });
    render(Tenants, { props: { health: null } });

    expect(await screen.findByText('Contoso')).toBeInTheDocument();
    expect(screen.getByText('Home Tenant')).toBeInTheDocument();
    // The home tenant shows a "home" badge and no Delete button.
    expect(screen.getByText('home')).toBeInTheDocument();
    expect(screen.getByText('2 tenants')).toBeInTheDocument();
    // Exactly one Delete button (the non-home tenant).
    expect(screen.getAllByText('Delete')).toHaveLength(1);
    expect(api.get).toHaveBeenCalledWith('/admin/api/tenants');
  });

  it('renders the empty state', async () => {
    api.get.mockResolvedValue({ value: [] });
    render(Tenants, { props: { health: null } });
    expect(await screen.findByText('0 tenants')).toBeInTheDocument();
  });

  it('posts only non-empty fields when creating', async () => {
    api.get.mockResolvedValue({ value: [] });
    api.post.mockResolvedValue({ id: 'new' });
    render(Tenants, { props: { health: null } });
    await screen.findByText('0 tenants');

    await fireEvent.click(screen.getByText('New tenant'));
    await fireEvent.input(screen.getByLabelText(/Display name/i), { target: { value: 'Fabrikam' } });
    // Leave initialDomain blank → it must be omitted from the body.
    await fireEvent.click(screen.getByText('Create'));

    expect(api.post).toHaveBeenCalledWith('/admin/api/tenants', { displayName: 'Fabrikam' });
  });

  it('surfaces API errors', async () => {
    api.get.mockRejectedValue(new Error('boom'));
    render(Tenants, { props: { health: null } });
    expect(await screen.findByText('boom')).toBeInTheDocument();
  });

  it('confirms and calls delete for a non-home tenant', async () => {
    api.get.mockResolvedValue({ value: [HOME, B] });
    api.del.mockResolvedValue(null);
    render(Tenants, { props: { health: null } });
    await screen.findByText('Contoso');

    await fireEvent.click(screen.getByText('Delete'));
    expect(globalThis.confirm).toHaveBeenCalled();
    expect(api.del).toHaveBeenCalledWith('/admin/api/tenants/' + B.id);
  });
});
