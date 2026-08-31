/* The chain list, loaded once and shared by every screen that needs it.
 *
 * The sidebar hint, the dashboard, the receipts feed and the Read-API links
 * all need "which chains does this server hold". Fetching it four times would
 * give four answers a moment apart, and the nav count could disagree with the
 * table it labels.
 */

import { computed, shallowRef, type ComputedRef } from 'vue'
import { ApiError } from '@/lib/api'
import { listChainIds } from '@/services/chains'

const ids = shallowRef<string[] | null>(null)
const error = shallowRef<ApiError | null>(null)
const pending = shallowRef(false)
let inFlight: Promise<void> | null = null

async function fetchOnce(): Promise<void> {
  pending.value = true
  error.value = null
  try {
    ids.value = await listChainIds()
  } catch (caught) {
    ids.value = null
    error.value =
      caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught))
  } finally {
    pending.value = false
    inFlight = null
  }
}

export function loadChainDirectory(force = false): Promise<void> {
  if (!force && (ids.value !== null || inFlight)) return inFlight ?? Promise.resolve()
  inFlight = fetchOnce()
  return inFlight
}

export interface ChainDirectory {
  ids: typeof ids
  error: typeof error
  pending: typeof pending
  /** Null until the list is known — NOT 0, which would claim an empty server. */
  count: ComputedRef<number | null>
  reload: () => Promise<void>
}

export function useChainDirectory(): ChainDirectory {
  void loadChainDirectory()
  return {
    ids,
    error,
    pending,
    count: computed(() => ids.value?.length ?? null),
    reload: () => loadChainDirectory(true),
  }
}
