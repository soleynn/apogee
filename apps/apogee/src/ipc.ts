import { Channel, invoke } from '@tauri-apps/api/core';

import type { CommandDto } from './generated/Command';
import type { EventDto } from './generated/Event';

export interface FutureCoreEvent {
  kind: 'futureEvent';
  rawKind: string;
  code: string;
}

export type CoreEvent = EventDto | FutureCoreEvent;

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

/** The desktop side's answer to `startup`, as it serializes it. */
export interface Startup {
  version: string;
  defaultRegion: string;
}

/** Reads what the frontend needs before it renders anything. */
export function startup(): Promise<Startup> {
  return invoke<Startup>('startup');
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
  return invoke<string>('execute', { command, onEvent: channel }).then((id) => {
    runId = id;
    for (const event of pending) onEvent(id, event);
    return id;
  });
}

/** Requests cancellation without treating a run that already ended as a failure. */
export function cancel(runId: string): Promise<boolean> {
  return invoke<boolean>('cancel', { runId });
}
