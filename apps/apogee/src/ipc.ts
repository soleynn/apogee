import { Channel, invoke } from '@tauri-apps/api/core';

import type { CommandDto } from './generated/Command';
import type { EventDto } from './generated/Event';
import type { CoreErrorDto } from './generated/CoreErrorDto';
import type { IpcErrorDto } from './generated/IpcError';
import type { SecretsReportDto } from './generated/SecretsReport';
import type { StartupDto } from './generated/Startup';

export interface FutureCoreEvent {
  kind: 'futureEvent';
  rawKind: string;
  code: string;
}

export type CoreEvent = EventDto | FutureCoreEvent;

export interface StartupStore extends StartupDto {
  activeProfile: string | null;
}

export interface CorruptStoreRecovery {
  code: string;
  path: string;
  backup: string;
}

/** A narrowed Tauri rejection containing only the shell's selected safe fields. */
export class IpcFailure extends Error {
  readonly code: string;
  readonly error: CoreErrorDto | null;

  constructor(failure: IpcErrorDto) {
    super(failure.code);
    this.name = 'IpcFailure';
    this.code = failure.code;
    this.error = failure.error;
  }
}

const ACTIVE_PROFILE_KEY = 'apogee.activeProfile';

const knownEventKinds = new Set([
  'state',
  'progress',
  'patch',
  'addon',
  'setup',
  'frontier',
  'firstRun',
  'import',
  'supportBundle',
  'prefix',
  'notice',
  'launchProgramExited',
  'error',
  'outcome',
  'unknown',
]);

function normalizeEvent(raw: unknown): CoreEvent {
  if (typeof raw === 'object' && raw !== null && 'kind' in raw) {
    const kind = String(raw.kind);
    if (knownEventKinds.has(kind)) return raw as EventDto;
    const code = 'code' in raw && typeof raw.code === 'string' ? raw.code : 'shell.event.unknown';
    return { kind: 'futureEvent', rawKind: kind, code };
  }
  return { kind: 'futureEvent', rawKind: 'invalid', code: 'shell.event.invalid' };
}

function normalizeFailure(raw: unknown): IpcFailure {
  if (raw instanceof IpcFailure) return raw;
  if (typeof raw === 'object' && raw !== null && 'code' in raw && typeof raw.code === 'string') {
    const error = 'error' in raw && (raw.error === null || typeof raw.error === 'object')
      ? (raw.error as CoreErrorDto | null)
      : null;
    return new IpcFailure({ code: raw.code, error });
  }
  return new IpcFailure({ code: 'shell.invoke.failed', error: null });
}

function invokeIpc<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const pending = args === undefined ? invoke<T>(command) : invoke<T>(command, args);
  return pending.catch((error: unknown) => Promise.reject(normalizeFailure(error)));
}

function localStorageOrUndefined(): Storage | undefined {
  try {
    return typeof localStorage === 'undefined' ? undefined : localStorage;
  } catch {
    return undefined;
  }
}

function readActiveProfile(): string | null {
  try {
    return localStorageOrUndefined()?.getItem(ACTIVE_PROFILE_KEY) ?? null;
  } catch {
    return null;
  }
}

function persistActiveProfile(profileId: string | null): void {
  try {
    const storage = localStorageOrUndefined();
    if (profileId === null) storage?.removeItem(ACTIVE_PROFILE_KEY);
    else storage?.setItem(ACTIVE_PROFILE_KEY, profileId);
  } catch {
    // The marker is an optional shell convenience. Storage denial must not block launcher state.
  }
}

function restoreActiveProfile(profiles: StartupDto['profiles']): string | null {
  const saved = readActiveProfile();
  if (saved === null || profiles.some((profile) => profile.id === saved)) return saved;
  persistActiveProfile(null);
  return null;
}

/** Reads what the frontend needs before it renders anything. */
export async function startup(): Promise<StartupStore> {
  const snapshot = await invokeIpc<StartupDto>('startup');
  return { ...snapshot, activeProfile: restoreActiveProfile(snapshot.profiles) };
}

/** Persists a validated shell-local selection without changing a domain record. */
export function selectActiveProfile(
  profileId: string | null,
  profiles: StartupDto['profiles'],
): string | null {
  const selected = profileId !== null && profiles.some((profile) => profile.id === profileId)
    ? profileId
    : null;
  persistActiveProfile(selected);
  return selected;
}

/** Probes credential-backend health independently from the local startup snapshot. */
export function secretsReport(): Promise<SecretsReportDto> {
  return invokeIpc<SecretsReportDto>('secrets_report');
}

/** Selects the structured corrupt-store recovery fields from any invoke rejection. */
export function corruptStoreRecovery(error: unknown): CorruptStoreRecovery | null {
  if (!(error instanceof IpcFailure) || error.error?.kind !== 'store') return null;
  const store = error.error.store;
  if (
    typeof store !== 'object'
    || store === null
    || !('kind' in store)
    || store.kind !== 'corrupt'
    || !('path' in store)
    || typeof store.path !== 'object'
    || store.path === null
    || !('display' in store.path)
    || typeof store.path.display !== 'string'
    || !('backup' in store)
    || typeof store.backup !== 'object'
    || store.backup === null
    || !('display' in store.backup)
    || typeof store.backup.display !== 'string'
  ) return null;
  return {
    code: error.code,
    path: store.path.display,
    backup: store.backup.display,
  };
}

/** Returns a stable presentation key for a narrowed or foreign rejection. */
export function failureCode(error: unknown): string {
  return error instanceof IpcFailure ? error.code : 'shell.invoke.failed';
}

/** Starts one ordered core stream and delivers every frame through the generated wire union. */
export function execute(
  command: CommandDto,
  onEvent: (runId: string, event: CoreEvent) => void,
): Promise<string> {
  const channel = new Channel<unknown>();
  const pending: CoreEvent[] = [];
  let runId: string | undefined;
  channel.onmessage = (raw) => {
    const event = normalizeEvent(raw);
    if (runId === undefined) pending.push(event);
    else onEvent(runId, event);
  };
  return invokeIpc<string>('execute', { command, onEvent: channel }).then((id) => {
    runId = id;
    for (const event of pending) onEvent(id, event);
    return id;
  });
}

/** Requests cancellation without treating a run that already ended as a failure. */
export function cancel(runId: string): Promise<boolean> {
  return invokeIpc<boolean>('cancel', { runId });
}
