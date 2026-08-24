import { Channel, invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';

import type { CommandDto } from './generated/Command';
import type { BundlePartDto } from './generated/BundlePart';
import type { CatalogEntryDto } from './generated/CatalogEntry';
import type { DefaultsDto } from './generated/DefaultsDto';
import type { EventDto } from './generated/Event';
import type { CoreErrorDto } from './generated/CoreErrorDto';
import type { IpcErrorDto } from './generated/IpcError';
import type { SecretsReportDto } from './generated/SecretsReport';
import type { NextActionDto } from './generated/NextAction';
import type { ResolvedSetupDto } from './generated/ResolvedSetup';
import type { StartupDto } from './generated/Startup';
import type { PassphrasePromptDto } from './generated/PassphrasePrompt';
import type { SecretsFileRemovalDto } from './generated/SecretsFileRemoval';
import type { SecretsFileStatusDto } from './generated/SecretsFileStatus';
import type { AccountDto } from './generated/AccountDto';
import type { DeleteSecretRequestDto } from './generated/DeleteSecretRequest';
import type { DisablePushedCodesRequestDto } from './generated/DisablePushedCodesRequest';
import type { ForgetSecretsRequestDto } from './generated/ForgetSecretsRequest';
import type { ForgetSecretsResultDto } from './generated/ForgetSecretsResult';
import type { NeverStoreResultDto } from './generated/NeverStoreResult';
import type { ProfileDto } from './generated/ProfileDto';
import type { ProfileRemovalDto } from './generated/ProfileRemoval';
import type { ProfileRemovalPlanDto } from './generated/ProfileRemovalPlan';
import type { RemoveProfileRequestDto } from './generated/RemoveProfileRequest';
import type { SetNeverStoreRequestDto } from './generated/SetNeverStoreRequest';
import type { SettingsDto } from './generated/SettingsDto';
import type { TotpImportResultDto } from './generated/TotpImportResult';
import type { UpdateAccountRequestDto } from './generated/UpdateAccountRequest';
import type { UpdateProfileRequestDto } from './generated/UpdateProfileRequest';
import type { UpdateSettingsRequestDto } from './generated/UpdateSettingsRequest';

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
const PASSPHRASE_REQUEST_EVENT = 'passphrase-request';

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

function invokeWithErasedBuffers<T>(
  command: string,
  args: Record<string, unknown>,
  buffers: number[][],
): Promise<T> {
  try {
    return invokeIpc<T>(command, args);
  } finally {
    for (const buffer of buffers) buffer.fill(0);
  }
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

/** Subscribes before an operation can ask for the sealed-file passphrase. */
export function onPassphrasePrompt(
  handler: (prompt: PassphrasePromptDto) => void,
): Promise<UnlistenFn> {
  return listen<PassphrasePromptDto>(PASSPHRASE_REQUEST_EVENT, (event) => handler(event.payload));
}

/** Answers one ambient prompt and erases the caller's byte buffer immediately after dispatch. */
export function submitPassphrase(requestId: string, passphrase: number[]): Promise<boolean> {
  return invokeWithErasedBuffers<boolean>('answer_passphrase_prompt', {
    requestId,
    answer: { kind: 'submit', passphrase },
  }, [passphrase]);
}

/** Cancels one ambient prompt without sending secret material. */
export function cancelPassphrase(requestId: string): Promise<boolean> {
  return invokeIpc<boolean>('answer_passphrase_prompt', {
    requestId,
    answer: { kind: 'cancel' },
  });
}

/** Reads the sealed credential file's header and in-process open state. */
export function secretsFileStatus(): Promise<SecretsFileStatusDto> {
  return invokeIpc<SecretsFileStatusDto>('secrets_file_status');
}

/** Prompts through the ambient bridge and primes the active encrypted backend. */
export function unlockSecretsFile(): Promise<SecretsFileStatusDto> {
  return invokeIpc<SecretsFileStatusDto>('unlock_secrets_file');
}

/** Creates an empty sealed credential file after explicit confirmation. */
export function createSecretsFile(
  passphrase: number[],
  confirmed: boolean,
): Promise<SecretsFileStatusDto> {
  return invokeWithErasedBuffers<SecretsFileStatusDto>('create_secrets_file', {
    request: { confirmed, passphrase },
  }, [passphrase]);
}

/** Re-seals the credential file and erases both inbound buffers after dispatch. */
export function changeSecretsFilePassphrase(
  current: number[],
  replacement: number[],
): Promise<SecretsFileStatusDto> {
  return invokeWithErasedBuffers<SecretsFileStatusDto>('change_secrets_file_passphrase', {
    request: { current, replacement },
  }, [current, replacement]);
}

/** Removes the sealed file only when the caller carries an explicit confirmation. */
export function removeSecretsFile(confirmed: boolean): Promise<SecretsFileRemovalDto> {
  return invokeIpc<SecretsFileRemovalDto>('remove_secrets_file', {
    request: { confirmed },
  });
}

/** Erases this process's cached derived key immediately. */
export function sealSecretsFile(): Promise<SecretsFileStatusDto> {
  return invokeIpc<SecretsFileStatusDto>('seal_secrets_file');
}

/** Updates only the editable account fields; secret policy remains core-owned. */
export function updateAccount(request: UpdateAccountRequestDto): Promise<AccountDto> {
  return invokeIpc<AccountDto>('update_account', { request });
}

/** Updates the path-free profile fields while preserving ownership and filesystem selections. */
export function updateProfile(request: UpdateProfileRequestDto): Promise<ProfileDto> {
  return invokeIpc<ProfileDto>('update_profile', { request });
}

/** Persists the complete launcher settings record after core validation. */
export function updateSettings(request: UpdateSettingsRequestDto): Promise<SettingsDto> {
  return invokeIpc<SettingsDto>('update_settings', { request });
}

/** Stores a password once and erases the caller's byte buffer after dispatch. */
export function storePassword(account: string, password: number[]): Promise<void> {
  return invokeWithErasedBuffers<void>('store_password', {
    request: { account, password },
  }, [password]);
}

/** Imports a generator secret without retaining its byte buffer in frontend state. */
export function importTotpSecret(account: string, secret: number[]): Promise<TotpImportResultDto> {
  return invokeWithErasedBuffers<TotpImportResultDto>('import_totp_secret', {
    request: { account, secret },
  }, [secret]);
}

/** Enables listener delivery only after the exact typed acknowledgment. */
export function usePushedCodes(account: string, confirmation: string): Promise<AccountDto> {
  return invokeIpc<AccountDto>('use_pushed_codes', {
    request: { account, confirmation },
  });
}

/** Returns an account from listener delivery to typed codes. */
export function disablePushedCodes(request: DisablePushedCodesRequestDto): Promise<AccountDto> {
  return invokeIpc<AccountDto>('disable_pushed_codes', { request });
}

/** Deletes one write-only secret after an inline confirmation. */
export function deleteSecret(request: DeleteSecretRequestDto): Promise<AccountDto> {
  return invokeIpc<AccountDto>('delete_secret', { request });
}

/** Sweeps every stored secret for an account after confirmation. */
export function forgetSecrets(
  request: ForgetSecretsRequestDto,
): Promise<ForgetSecretsResultDto> {
  return invokeIpc<ForgetSecretsResultDto>('forget_secrets', { request });
}

/** Changes an account's keep-nothing policy through core's ordered sweep contract. */
export function setNeverStore(request: SetNeverStoreRequestDto): Promise<NeverStoreResultDto> {
  return invokeIpc<NeverStoreResultDto>('set_never_store', { request });
}

/** Opens one opaque, single-use profile-removal decision. */
export function planProfileRemoval(profile: string): Promise<ProfileRemovalPlanDto> {
  return invokeIpc<ProfileRemovalPlanDto>('plan_profile_removal', { profile });
}

/** Invalidates the matching pending profile-removal decision. */
export function cancelProfileRemoval(requestId: string): Promise<boolean> {
  return invokeIpc<boolean>('cancel_profile_removal', { requestId });
}

/** Consumes the exact plan the confirmation displayed. */
export function removeProfile(request: RemoveProfileRequestDto): Promise<ProfileRemovalDto> {
  return invokeIpc<ProfileRemovalDto>('remove_profile', { request });
}

/** Reads the core-selected action for one profile without deriving readiness in the frontend. */
export function nextAction(profile: string): Promise<NextActionDto> {
  return invokeIpc<NextActionDto>('next_action', { profile });
}

/** Reads core-owned settings and launch defaults for structural comparisons and resets. */
export function defaults(): Promise<DefaultsDto> {
  return invokeIpc<DefaultsDto>('defaults');
}

/** Reads the effective launch setup together with the authority behind every value. */
export function resolvedSetup(profile: string): Promise<ResolvedSetupDto[]> {
  return invokeIpc<ResolvedSetupDto[]>('resolved_setup', { profile });
}

/** Reads authenticated runner rows and local installation state. */
export function runnerCatalog(): Promise<CatalogEntryDto[]> {
  return invokeIpc<CatalogEntryDto[]>('runner_catalog');
}

/** Reads authenticated DXVK rows and the selected prefix's installation state. */
export function dxvkCatalog(profile: string): Promise<CatalogEntryDto[]> {
  return invokeIpc<CatalogEntryDto[]>('dxvk_catalog', { profile });
}

/** Reads core's fixed, public-safe diagnostic report as one opaque document. */
export function systemReport(profile: string | null = null): Promise<string> {
  return invokeIpc<string>('system_report', { profile });
}

/** Reads core's ordered preview of the entries included in a support archive. */
export function supportBundleContents(): Promise<BundlePartDto[]> {
  return invokeIpc<BundlePartDto[]>('support_bundle_contents');
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
