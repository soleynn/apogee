import { Channel, invoke } from '@tauri-apps/api/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { cancel, execute, startup } from './ipc';

vi.mock('@tauri-apps/api/core', () => ({
  Channel: vi.fn(function MockChannel(this: { onmessage?: unknown }) {
    this.onmessage = undefined;
  }),
  invoke: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('startup', () => {
  it('names the desktop command and hands back what it answered', async () => {
    const answer = { version: '0.0.0', defaultRegion: 'global' };
    vi.mocked(invoke).mockResolvedValue(answer);

    await expect(startup()).resolves.toEqual(answer);
    expect(invoke).toHaveBeenCalledWith('startup');
  });
});

describe('run commands', () => {
  it('keeps one channel for the complete event stream', async () => {
    const command = { kind: 'launch' as const, profile: 'profile-id' };
    const onEvent = vi.fn();
    vi.mocked(invoke).mockResolvedValue('run-id');

    await expect(execute(command, onEvent)).resolves.toBe('run-id');

    expect(Channel).toHaveBeenCalledOnce();
    const channel = vi.mocked(Channel).mock.instances[0];
    expect(channel?.onmessage).toEqual(expect.any(Function));
    expect(invoke).toHaveBeenCalledWith('execute', {
      command,
      onEvent: channel,
    });
  });

  it('buffers early frames until it can attach the run id', async () => {
    let resolveRun: ((runId: string) => void) | undefined;
    vi.mocked(invoke).mockReturnValue(
      new Promise((resolve) => {
        resolveRun = resolve;
      }),
    );
    const onEvent = vi.fn();
    const running = execute({ kind: 'launch', profile: 'profile-id' }, onEvent);
    const channel = vi.mocked(Channel).mock.instances[0];

    channel?.onmessage?.({ kind: 'outcome', code: 'outcome-succeeded', outcome: 'succeeded' });
    expect(onEvent).not.toHaveBeenCalled();

    resolveRun?.('run-id');
    await expect(running).resolves.toBe('run-id');
    expect(onEvent).toHaveBeenCalledWith('run-id', {
      kind: 'outcome',
      code: 'outcome-succeeded',
      outcome: 'succeeded',
    });
  });

  it('normalizes future frames without overlapping known discriminants', async () => {
    const onEvent = vi.fn();
    vi.mocked(invoke).mockResolvedValue('run-id');
    await execute({ kind: 'launch', profile: 'profile-id' }, onEvent);
    const channel = vi.mocked(Channel).mock.instances[0];

    channel?.onmessage?.({ kind: 'newCoreFrame', code: 'new-code' });
    expect(onEvent).toHaveBeenCalledWith('run-id', {
      kind: 'futureEvent',
      rawKind: 'newCoreFrame',
      code: 'new-code',
    });
  });

  it('forwards cancellation by run id', async () => {
    vi.mocked(invoke).mockResolvedValue(true);

    await expect(cancel('run-id')).resolves.toBe(true);
    expect(invoke).toHaveBeenCalledWith('cancel', { runId: 'run-id' });
  });
});
