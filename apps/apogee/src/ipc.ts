import { invoke } from '@tauri-apps/api/core';

/** The desktop side's answer to `startup`, as it serializes it. */
export interface Startup {
  version: string;
  defaultRegion: string;
}

/** Reads what the frontend needs before it renders anything. */
export function startup(): Promise<Startup> {
  return invoke<Startup>('startup');
}
