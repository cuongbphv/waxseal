/* The counts the sidebar puts at the right of a nav row.
 *
 * A hint is only ever a number this app is already holding. The design's "6"
 * and "#84" were placeholders, and a badge that guesses is the same failure as
 * a stat card that guesses — just smaller and less likely to be checked.
 *
 * `null` means "not counted", and the row renders nothing rather than a zero.
 * Sources that would cost a request per chain are deliberately not wired: a
 * badge is not worth N round trips, and blank is an honest way to say so.
 */

import { computed, shallowRef, type ComputedRef } from 'vue'
import { listImports } from '@/services/imports'
import { PROVIDERS } from '@/content'
import type { HintSource } from '@/lib/nav'
import { useChainDirectory } from './useChainDirectory'

const importCount = shallowRef<number | null>(null)
let importsRequested = false

async function loadImportCount(): Promise<void> {
  if (importsRequested) return
  importsRequested = true
  try {
    importCount.value = (await listImports()).length
  } catch {
    /* A count nobody could read stays null: the row shows nothing, which is
     * what "we do not know" looks like. */
    importCount.value = null
  }
}

export function useNavCounts(): { countFor: ComputedRef<(source: HintSource) => number | null> } {
  const chains = useChainDirectory()
  void loadImportCount()

  return {
    countFor: computed(() => (source: HintSource) => {
      if (source === 'chains') return chains.count.value
      if (source === 'imports') return importCount.value
      if (source === 'integrations') return PROVIDERS.length
      return null
    }),
  }
}
