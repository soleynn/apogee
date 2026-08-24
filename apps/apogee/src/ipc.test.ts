import { Channel, invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  IpcFailure,
  cancelPassphrase,
  cancel,
  changeSecretsFilePassphrase,
  corruptStoreRecovery,
  createSecretsFile,
  defaults,
  dxvkCatalog,
  execute,
  nextAction,
  onPassphrasePrompt,
  removeSecretsFile,
  resolvedSetup,
  runnerCatalog,
  secretsReport,
  secretsFileStatus,
  sealSecretsFile,
  selectActiveProfile,
  startup,
  supportBundleContents,
  submitPassphrase,
  systemReport,
  unlockSecretsFile,
} from './ipc';

vi.mock('@tauri-apps/api/core', () => ({
  Channel: vi.fn(function MockChannel(this: { onmessage?: unknown }) {
    this.onmessage = undefined;
  }),
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(listen).mockResolvedValue(vi.fn());
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
});

describe('sealed secret file', () => {
  it('forwards only the typed ambient prompt payload', async () => {
    let receive: ((event: { payload: { requestId: string } }) => void) | undefined;
    const unlisten = vi.fn();
    vi.mocked(listen).mockImplementation((_name, handler) => {
      receive = handler as typeof receive;
      return Promise.resolve(unlisten);
    });
    const handler = vi.fn();

    await expect(onPassphrasePrompt(handler)).resolves.toBe(unlisten);
    expect(listen).toHaveBeenCalledWith('passphrase-request', expect.any(Function));
    receive?.({ payload: { requestId: 'request-id' } });
    expect(handler).toHaveBeenCalledWith({ requestId: 'request-id' });
  });

  it('submits bytes once and overwrites them before the invoke settles', async () => {
    let settle: ((accepted: boolean) => void) | undefined;
    let sent: unknown;
    vi.mocked(invoke).mockImplementation((_command, args) => {
      sent = structuredClone(args);
      return new Promise((resolve) => {
        settle = resolve;
      });
    });
    const bytes = [115, 101, 99, 114, 101, 116];

    const pending = submitPassphrase('request-id', bytes);
    expect(sent).toEqual({
      requestId: 'request-id',
      answer: { kind: 'submit', passphrase: [115, 101, 99, 114, 101, 116] },
    });
    expect(bytes).toEqual([0, 0, 0, 0, 0, 0]);

    settle?.(true);
    await expect(pending).resolves.toBe(true);
  });

  it('overwrites submitted bytes when dispatch throws before returning a promise', () => {
    vi.mocked(invoke).mockImplementation(() => {
      throw new Error('synchronous bridge failure');
    });
    const bytes = [9, 8, 7];

    expect(() => submitPassphrase('request-id', bytes)).toThrow('synchronous bridge failure');
    expect(bytes).toEqual([0, 0, 0]);
  });

  it('uses the closed cancel response with no secret field', async () => {
    vi.mocked(invoke).mockResolvedValue(true);
    await expect(cancelPassphrase('request-id')).resolves.toBe(true);
    expect(invoke).toHaveBeenCalledWith('answer_passphrase_prompt', {
      requestId: 'request-id',
      answer: { kind: 'cancel' },
    });
  });

  it('keeps every lifecycle invocation explicit and erases mutation inputs', async () => {
    const sent: Array<{ command: string; args: unknown }> = [];
    vi.mocked(invoke).mockImplementation((command, args) => {
      sent.push({ command, args: structuredClone(args) });
      return Promise.resolve({ state: { kind: 'absent' }, isOpen: false });
    });
    const create = [1, 2, 3];
    const current = [4, 5];
    const replacement = [6, 7];

    await secretsFileStatus();
    await unlockSecretsFile();
    await createSecretsFile(create, true);
    await changeSecretsFilePassphrase(current, replacement);
    await removeSecretsFile(true);
    await sealSecretsFile();

    expect(sent).toEqual([
      { command: 'secrets_file_status', args: undefined },
      { command: 'unlock_secrets_file', args: undefined },
      {
        command: 'create_secrets_file',
        args: { request: { confirmed: true, passphrase: [1, 2, 3] } },
      },
      {
        command: 'change_secrets_file_passphrase',
        args: { request: { current: [4, 5], replacement: [6, 7] } },
      },
      {
        command: 'remove_secrets_file',
        args: { request: { confirmed: true } },
      },
      { command: 'seal_secrets_file', args: undefined },
    ]);
    expect(create).toEqual([0, 0, 0]);
    expect(current).toEqual([0, 0]);
    expect(replacement).toEqual([0, 0]);
  });

  it('normalizes lifecycle failures through the common IPC envelope', async () => {
    vi.mocked(invoke).mockRejectedValue({
      code: 'err-secrets',
      error: { kind: 'secrets', secrets: 'wrongPassphrase' },
    });

    await expect(unlockSecretsFile()).rejects.toMatchObject({
      name: 'IpcFailure',
      code: 'err-secrets',
      error: { kind: 'secrets', secrets: 'wrongPassphrase' },
    });
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
