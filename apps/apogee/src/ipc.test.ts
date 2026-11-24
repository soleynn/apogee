import { Channel, invoke } from '@tauri-apps/api/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  IpcFailure,
  cancel,
  corruptStoreRecovery,
  defaults,
  dxvkCatalog,
  execute,
  nextAction,
  resolvedSetup,
  runnerCatalog,
  secretsReport,
  selectActiveProfile,
  startup,
  supportBundleContents,
  systemReport,
} from './ipc';

vi.mock('@tauri-apps/api/core', () => ({
  Channel: vi.fn(function MockChannel(this: { onmessage?: unknown }) {
    this.onmessage = undefined;
  }),
  invoke: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
});

describe('startup', () => {
  it('names the desktop command and hands back what it answered', async () => {
    const answer = {
      version: '0.0.0',
      profiles: [],
      accounts: [],
      settings: {},
      defaults: {},
    };
    vi.mocked(invoke).mockResolvedValue(answer);

    await expect(startup()).resolves.toEqual({ ...answer, activeProfile: null });
    expect(invoke).toHaveBeenCalledWith('startup');
  });

  it('restores only a last-used profile that still exists', async () => {
    const profile = { id: 'present-profile' };
    localStorage.setItem('apogee.activeProfile', profile.id);
    vi.mocked(invoke).mockResolvedValue({
      version: '0.0.0',
      profiles: [profile],
      accounts: [],
      settings: {},
      defaults: {},
    });

    await expect(startup()).resolves.toMatchObject({ activeProfile: profile.id });

    localStorage.setItem('apogee.activeProfile', 'deleted-profile');
    await expect(startup()).resolves.toMatchObject({ activeProfile: null });
    expect(localStorage.getItem('apogee.activeProfile')).toBeNull();
  });

  it('leaves missing and zero-profile selections empty', async () => {
    vi.mocked(invoke).mockResolvedValue({
      version: '0.0.0',
      profiles: [],
      accounts: [],
      settings: {},
      defaults: {},
    });

    await expect(startup()).resolves.toMatchObject({ activeProfile: null });
    expect(selectActiveProfile('missing', [])).toBeNull();
    expect(localStorage.getItem('apogee.activeProfile')).toBeNull();
  });

  it('normalizes corrupt-store failures and keeps the recovery paths', async () => {
    vi.mocked(invoke).mockRejectedValue({
      code: 'err-store',
      error: {
        kind: 'store',
        store: {
          kind: 'corrupt',
          path: { display: 'settings.json', value: { kind: 'utf8', value: 'settings.json' } },
          backup: {
            display: 'settings.json.corrupt',
            value: { kind: 'utf8', value: 'settings.json.corrupt' },
          },
        },
      },
    });

    const failure = await startup().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(IpcFailure);
    expect(corruptStoreRecovery(failure)).toEqual({
      code: 'err-store',
      path: 'settings.json',
      backup: 'settings.json.corrupt',
    });
  });

  it('does not throw while selecting recovery from a malformed future error', async () => {
    vi.mocked(invoke).mockRejectedValue({ code: 'err-store', error: { kind: 'store' } });

    const failure = await startup().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(IpcFailure);
    expect(corruptStoreRecovery(failure)).toBeNull();
  });

  it('treats denied marker storage as optional', async () => {
    vi.stubGlobal('localStorage', {
      getItem: () => { throw new Error('denied'); },
      setItem: () => { throw new Error('denied'); },
      removeItem: () => { throw new Error('denied'); },
    });
    vi.mocked(invoke).mockResolvedValue({
      version: '0.0.0',
      profiles: [],
      accounts: [],
      settings: {},
      defaults: {},
    });

    await expect(startup()).resolves.toMatchObject({ activeProfile: null });
    expect(selectActiveProfile('missing', [])).toBeNull();
  });

  it('keeps credential probing out of the startup call', async () => {
    const answer = {
      backend: 'null',
      state: 'notStoring',
      sandbox: null,
      secretsPath: { display: 'secrets.bin', value: { kind: 'utf8', value: 'secrets.bin' } },
    };
    vi.mocked(invoke).mockResolvedValue(answer);

    await expect(secretsReport()).resolves.toEqual(answer);
    expect(invoke).toHaveBeenCalledWith('secrets_report');
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

describe('direct core reads', () => {
  it('keeps profile identity explicit on profile-scoped reads', async () => {
    vi.mocked(invoke).mockResolvedValue([]);

    await nextAction('profile-id');
    await resolvedSetup('profile-id');
    await dxvkCatalog('profile-id');

    expect(invoke).toHaveBeenNthCalledWith(1, 'next_action', { profile: 'profile-id' });
    expect(invoke).toHaveBeenNthCalledWith(2, 'resolved_setup', { profile: 'profile-id' });
    expect(invoke).toHaveBeenNthCalledWith(3, 'dxvk_catalog', { profile: 'profile-id' });
  });

  it('uses independent methods for catalogs, defaults, and support previews', async () => {
    vi.mocked(invoke).mockResolvedValue([]);

    await runnerCatalog();
    await defaults();
    await supportBundleContents();

    expect(invoke).toHaveBeenNthCalledWith(1, 'runner_catalog');
    expect(invoke).toHaveBeenNthCalledWith(2, 'defaults');
    expect(invoke).toHaveBeenNthCalledWith(3, 'support_bundle_contents');
  });

  it('requests core-composed reports with an optional profile only', async () => {
    vi.mocked(invoke).mockResolvedValue('report');

    await expect(systemReport()).resolves.toBe('report');
    await expect(systemReport('profile-id')).resolves.toBe('report');

    expect(invoke).toHaveBeenNthCalledWith(1, 'system_report', { profile: null });
    expect(invoke).toHaveBeenNthCalledWith(2, 'system_report', { profile: 'profile-id' });
  });

  it('normalizes failures from direct reads through the same boundary', async () => {
    vi.mocked(invoke).mockRejectedValue({ code: 'err-runtime', error: null });

    await expect(runnerCatalog()).rejects.toMatchObject({
      name: 'IpcFailure',
      code: 'err-runtime',
    });
  });
});
