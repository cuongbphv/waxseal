/* The key list, the mint, and the revoke.
 *
 * Two things here are load-bearing and neither is about layout.
 *
 * The minted plaintext lives in ONE ref and nowhere else. It is not written to
 * sessionStorage, not appended to the list, not passed to `console`, and there
 * is no function on this composable that could fetch it again — the server kept
 * only a SHA-256, so a "reveal" affordance would be a button that cannot work.
 * `dismissMinted` drops it, and after that it is gone from the browser.
 *
 * A revoke reports what THAT CALL did. `{revoked: false}` means the key was
 * already revoked or no key has that id; rendering it as a success would be
 * telling an operator a credential was withdrawn on the strength of a response
 * that said nothing of the sort.
 */

import { onScopeDispose, ref, shallowRef, type Ref, type ShallowRef } from 'vue'
import type { ApiError, ApiKeyRecord, MintedKey } from '@/lib/api'
import { listKeys, mintKey, revokeKey, toApiError } from '@/services/operators'
import { loadServerFacts } from '@/services/serverFacts'
import { useAsyncData, type AsyncData } from './useAsyncData'

/** What one revoke call did, with the key it was about. `revoked: false` is an
 * outcome, not a failure — a failure is `revokeError`. */
export interface RevokeOutcome {
  key: ApiKeyRecord
  revoked: boolean
}

export interface UseApiKeys {
  keys: AsyncData<ApiKeyRecord[]>
  minting: Ref<boolean>
  mintError: ShallowRef<ApiError | null>
  /** The plaintext, held only until dismissed. Nothing else reads it. */
  minted: ShallowRef<MintedKey | null>
  mint: (username: string, label: string) => Promise<boolean>
  dismissMinted: () => void
  /** The `key_id` a revoke is in flight for, so one row can show it. */
  revoking: Ref<string | null>
  revokeError: ShallowRef<ApiError | null>
  revokeOutcome: ShallowRef<RevokeOutcome | null>
  revoke: (key: ApiKeyRecord) => Promise<void>
}

export function useApiKeys(): UseApiKeys {
  const keys = useAsyncData<ApiKeyRecord[]>(() => listKeys())

  const minting = ref(false)
  const mintError = shallowRef<ApiError | null>(null)
  const minted = shallowRef<MintedKey | null>(null)

  function dismissMinted(): void {
    minted.value = null
  }

  /* Leaving the screen dismisses it too. A secret that survives a navigation
   * is a secret still on the page when someone else walks up to the laptop. */
  onScopeDispose(dismissMinted)

  async function mint(username: string, label: string): Promise<boolean> {
    minting.value = true
    mintError.value = null
    minted.value = null
    try {
      minted.value = await mintKey(username, label)
      await keys.run()
      /* Seeding a key is what closes an open server: `/v1/meta` starts
       * reporting `write_auth: bearer_required` as soon as one exists, so the
       * "this server is open" notice has to be re-read, not left standing. */
      void loadServerFacts()
      return true
    } catch (caught) {
      mintError.value = toApiError(caught)
      return false
    } finally {
      minting.value = false
    }
  }

  const revoking = ref<string | null>(null)
  const revokeError = shallowRef<ApiError | null>(null)
  const revokeOutcome = shallowRef<RevokeOutcome | null>(null)

  async function revoke(key: ApiKeyRecord): Promise<void> {
    revoking.value = key.key_id
    revokeError.value = null
    revokeOutcome.value = null
    try {
      revokeOutcome.value = { key, revoked: await revokeKey(key.key_id) }
      await keys.run()
    } catch (caught) {
      revokeError.value = toApiError(caught)
    } finally {
      revoking.value = null
    }
  }

  return {
    keys,
    minting,
    mintError,
    minted,
    mint,
    dismissMinted,
    revoking,
    revokeError,
    revokeOutcome,
    revoke,
  }
}
