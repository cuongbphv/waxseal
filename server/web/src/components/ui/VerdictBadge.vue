<script setup lang="ts">
/* A CLI outcome as the design's verdict pill: `ok · 0`, `unverifiable · 2`,
 * `broken · 1`.
 *
 * The exit code is the point. An operator comparing this screen against
 * `waxseal verify` in a terminal matches on the number, and exit 2 is
 * "unverifiable" — a statement about this verifier, not a milder kind of
 * failure. The `title` carries the whole sentence, because neither a word nor
 * a number is one.
 *
 * All seven statuses render, including the ones that produced no verdict at
 * all: `absent`, `unavailable`, `usage_error`, `unexpected_exit` come through
 * `states.ts` with their own word and the neutral tone. A view never switches
 * on a status string, so a status this build has not seen still arrives with
 * a word rather than as a blank cell.
 */

import { computed } from 'vue'
import type { Outcome } from '@/lib/api'
import { stateOf } from '@/lib/states'
import { useI18n } from '@/lib/i18n'
import StatusPill from './StatusPill.vue'

const props = defineProps<{ outcome: Outcome }>()

const { t } = useI18n()

const state = computed(() => stateOf(props.outcome.status))

/* No exit code is its own fact: the command never ran. Omitted rather than
 * printed as a placeholder digit. */
const suffix = computed(() =>
  props.outcome.exit_code === null ? undefined : String(props.outcome.exit_code),
)

const title = computed(() => {
  const exit =
    props.outcome.exit_code === null
      ? t('exitNone')
      : t('exitLabel', { code: props.outcome.exit_code })
  return `${exit} — ${t(state.value.explanationKey)}`
})
</script>

<template>
  <StatusPill :tone="state.tone" :label="state.label" :suffix="suffix" :title="title" />
</template>
