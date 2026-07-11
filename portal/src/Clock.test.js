import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Clock from './Clock.svelte';

const STATE = { nowISO: '2026-07-11T00:00:00Z', offsetSeconds: 0, frozen: false };

describe('Clock view', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders clock state from the API', async () => {
    api.get.mockResolvedValue(STATE);
    render(Clock, {});
    expect(await screen.findByText('2026-07-11T00:00:00Z')).toBeInTheDocument();
    expect(screen.getByText('Freeze')).toBeInTheDocument(); // frozen:false → offer Freeze
    expect(api.get).toHaveBeenCalledWith('/admin/api/clock');
  });

  it('advances by a preset', async () => {
    api.get.mockResolvedValue(STATE);
    api.post.mockResolvedValue({ ...STATE, offsetSeconds: 3600 });
    render(Clock, {});
    await screen.findByText('2026-07-11T00:00:00Z');
    await fireEvent.click(screen.getByText('+1 hour'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/clock', { advanceSeconds: 3600 });
  });

  it('advances by a custom number of seconds', async () => {
    api.get.mockResolvedValue(STATE);
    api.post.mockResolvedValue(STATE);
    render(Clock, {});
    await screen.findByText('2026-07-11T00:00:00Z');
    await fireEvent.input(screen.getByLabelText(/Advance by/i), { target: { value: '120' } });
    await fireEvent.click(screen.getByText('Advance'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/clock', { advanceSeconds: 120 });
  });

  it('freezes and resets to real time', async () => {
    api.get.mockResolvedValue(STATE);
    api.post.mockResolvedValue(STATE);
    api.del.mockResolvedValue(null);
    render(Clock, {});
    await screen.findByText('2026-07-11T00:00:00Z');
    await fireEvent.click(screen.getByText('Freeze'));
    expect(api.post).toHaveBeenCalledWith('/admin/api/clock', { frozen: true });
    await fireEvent.click(screen.getByText('Reset to real time'));
    expect(api.del).toHaveBeenCalledWith('/admin/api/clock');
  });

  it('surfaces errors', async () => {
    api.get.mockRejectedValue(new Error('clock down'));
    render(Clock, {});
    expect(await screen.findByText('clock down')).toBeInTheDocument();
  });
});
