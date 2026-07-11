import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';

vi.mock('./api.js', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() },
  copy: vi.fn(),
}));
import { api } from './api.js';
import Faults from './Faults.svelte';

describe('Faults view', () => {
  beforeEach(() => vi.clearAllMocks());

  it('reflects a loaded fault config as "configured"', async () => {
    api.get.mockResolvedValue({ tokenError: 'invalid_grant', tokenErrorDescription: '', tokenLatencyMs: 0, probability: 1 });
    render(Faults, {});
    expect(await screen.findByText('A fault is configured.')).toBeInTheDocument();
    expect(api.get).toHaveBeenCalledWith('/admin/api/faults');
  });

  it('arms faults, coercing latency and probability to numbers', async () => {
    api.get.mockResolvedValue({ tokenError: '', tokenErrorDescription: '', tokenLatencyMs: 0, probability: 1 });
    api.post.mockResolvedValue(null);
    render(Faults, {});
    await screen.findByText('No fault configured.');

    await fireEvent.change(screen.getByLabelText(/Forced token error/i), { target: { value: 'temporarily_unavailable' } });
    await fireEvent.input(screen.getByLabelText(/Latency/i), { target: { value: '250' } });
    await fireEvent.input(screen.getByLabelText(/Probability/i), { target: { value: '0.5' } });
    await fireEvent.click(screen.getByText('Arm faults'));

    expect(api.post).toHaveBeenCalledWith('/admin/api/faults', {
      tokenError: 'temporarily_unavailable',
      tokenErrorDescription: '',
      tokenLatencyMs: 250,
      probability: 0.5,
    });
    expect(await screen.findByText('Faults armed.')).toBeInTheDocument();
  });

  it('disarms all faults', async () => {
    api.get.mockResolvedValue({ tokenError: '', tokenErrorDescription: '', tokenLatencyMs: 0, probability: 1 });
    api.del.mockResolvedValue(null);
    render(Faults, {});
    await screen.findByText('Disarm all');
    await fireEvent.click(screen.getByText('Disarm all'));
    expect(api.del).toHaveBeenCalledWith('/admin/api/faults');
    expect(await screen.findByText('All faults disarmed.')).toBeInTheDocument();
  });

  it('surfaces errors', async () => {
    api.get.mockRejectedValue(new Error('faults down'));
    render(Faults, {});
    expect(await screen.findByText('faults down')).toBeInTheDocument();
  });
});
