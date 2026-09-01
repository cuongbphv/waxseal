/* One request, three rendered outcomes: pending, loaded, failed-with-reason.
 *
 * There is deliberately no fourth. A screen that cannot say which of the
 * three it is in will end up drawing an empty table over a failed request,
 * which reads as "nothing here" — a claim the request never supported.
 */

import { ref, shallowRef, watch, type Ref, type ShallowRef, type WatchSource } from 'vue'
import { ApiError } from '@/lib/api'

export interface AsyncData<T> {
  data: ShallowRef<T | null>
  error: ShallowRef<ApiError | null>
  pending: Ref<boolean>
  /** False until the first attempt. "Not started" is not "loaded nothing". */
  started: Ref<boolean>
  run: () => Promise<void>
}

export interface AsyncDataOptions {
  immediate?: boolean
  /** Re-run whenever any of these change — a chain id in the route, say. */
  watching?: WatchSource[]
}

export function useAsyncData<T>(
  fn: () => Promise<T>,
  options: AsyncDataOptions = {},
): AsyncData<T> {
  const data = shallowRef<T | null>(null)
  const error = shallowRef<ApiError | null>(null)
  const pending = ref(false)
  const started = ref(false)

  /* Only the newest run may write the refs: a slower earlier request must not
   * overwrite a newer answer with a stale one when the operator switches
   * chains mid-flight. */
  let generation = 0

  async function run(): Promise<void> {
    const mine = ++generation
    pending.value = true
    started.value = true
    error.value = null
    try {
      const value = await fn()
      if (mine !== generation) return
      data.value = value
    } catch (caught) {
      if (mine !== generation) return
      data.value = null
      error.value =
        caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught))
    } finally {
      if (mine === generation) pending.value = false
    }
  }

  if (options.watching?.length) {
    watch(options.watching, () => void run())
  }
  if (options.immediate !== false) void run()

  return { data, error, pending, started, run }
}
