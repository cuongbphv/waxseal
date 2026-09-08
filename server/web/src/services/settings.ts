/* Server settings the console can read and change.

 * Views ask "what is stored?" and "write this key", not PUT /v1/settings/:key.
 * The transport stays in `lib/api.ts`.
 */

import { api, type ServerSettings } from '@/lib/api'

export async function loadSettings(): Promise<ServerSettings> {
  return api.settings()
}

export async function saveSetting(
  key: string,
  value: string,
): Promise<{ key: string; value: string; source: string }> {
  return api.setSetting(key, value)
}

export async function resetSetting(
  key: string,
): Promise<{ key: string; reset: boolean }> {
  return api.resetSetting(key)
}
