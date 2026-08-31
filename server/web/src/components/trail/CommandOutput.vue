<script setup lang="ts">
/* Run one read-only CLI command and print its verdict, its argv and its
 * stdout, verbatim.
 *
 * It loads on mount, so mounting it behind a capability gate is what makes the
 * request conditional — the gate decides whether the command exists, this
 * decides nothing. Used by the segments and preflight screens, which are the
 * two that turn real when their workstream lands.
 */

import type { Outcome } from '@/lib/api'
import { useAsyncData } from '@/composables/useAsyncData'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import OutputPanel from '@/components/ui/OutputPanel.vue'
import VerdictBadge from '@/components/ui/VerdictBadge.vue'
import TokenField from '@/components/app/TokenField.vue'

const props = defineProps<{ run: () => Promise<Outcome> }>()

const outcome = useAsyncData<Outcome>(() => props.run())
</script>

<template>
  <AsyncBlock
    :pending="outcome.pending.value"
    :started="outcome.started.value"
    :error="outcome.error.value"
    @retry="outcome.run"
  >
    <template #unauthorized><TokenField /></template>
    <div v-if="outcome.data.value" class="stack">
      <VerdictBadge :outcome="outcome.data.value" />
      <OutputPanel
        :argv="outcome.data.value.argv"
        :stdout="outcome.data.value.stdout"
        :stderr="outcome.data.value.stderr"
        :exit-code="outcome.data.value.exit_code"
      />
    </div>
  </AsyncBlock>
</template>

<style scoped>
.stack {
  display: flex;
  flex-direction: column;
  gap: var(--content-gap);
  align-items: flex-start;
}

.stack > :last-child {
  align-self: stretch;
}
</style>
