/* The operator list and the one form that adds to it.
 *
 * A create is not a read, so it does not go through `useAsyncData`: its three
 * refusals are the whole point of the screen and each needs a sentence of its
 * own. What this composable exposes is the ApiError itself, so the view can ask
 * `createOperatorErrorKey` which of the three it was rather than switching on a
 * status code in markup.
 */

import { ref, shallowRef, type Ref, type ShallowRef } from 'vue'
import type { ApiError, NewOperator, Operator } from '@/lib/api'
import { createOperator, listOperators, toApiError } from '@/services/operators'
import { loadServerFacts } from '@/services/serverFacts'
import { useAsyncData, type AsyncData } from './useAsyncData'

export interface UseOperators {
  operators: AsyncData<Operator[]>
  creating: Ref<boolean>
  createError: ShallowRef<ApiError | null>
  /** The operator the LAST create actually made, so the confirmation names a
   * record the server returned rather than the form's own draft. */
  created: ShallowRef<Operator | null>
  invite: (draft: NewOperator) => Promise<boolean>
}

export function useOperators(): UseOperators {
  const operators = useAsyncData<Operator[]>(() => listOperators())
  const creating = ref(false)
  const createError = shallowRef<ApiError | null>(null)
  const created = shallowRef<Operator | null>(null)

  async function invite(draft: NewOperator): Promise<boolean> {
    creating.value = true
    createError.value = null
    created.value = null
    try {
      created.value = await createOperator(draft)
      await operators.run()
      /* A new operator can change what the server says about itself — the
       * first one on an open deployment is a step toward closing it — so the
       * shared facts are re-read rather than left to go stale. */
      void loadServerFacts()
      return true
    } catch (caught) {
      createError.value = toApiError(caught)
      return false
    } finally {
      creating.value = false
    }
  }

  return { operators, creating, createError, created, invite }
}
