import { invoke } from '@tauri-apps/api/core';
import { describe, expect, it, vi } from 'vitest';

import { startup } from './ipc';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

describe('startup', () => {
  it('names the desktop command and hands back what it answered', async () => {
    const answer = { version: '0.0.0', defaultRegion: 'global' };
    vi.mocked(invoke).mockResolvedValue(answer);

    await expect(startup()).resolves.toEqual(answer);
    expect(invoke).toHaveBeenCalledWith('startup');
  });
});
