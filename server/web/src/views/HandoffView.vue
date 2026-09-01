<script setup lang="ts">
/* `verify-handoff` — D3's cross-trail binding check.
 *
 * Two chains, and which is which matters: the delegate trail carries the
 * binding entries, the origin is the history they name. Both are picked from
 * this server's own chain list rather than typed, so a request cannot name an
 * arbitrary file as the origin.
 *
 * "Nothing to check" and "every binding holds" are both exit 0 and are NOT the
 * same statement, which is why the command's own stdout is shown rather than a
 * verdict word chosen here.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'
import { runVerifyHandoff } from '@/services/chains'
import { useChainDirectory } from '@/composables/useChainDirectory'
import PageHeader from '@/components/ui/PageHeader.vue'
import CommandForm, { type Field } from '@/components/app/CommandForm.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const chains = computed(() => directory.ids.value ?? [])

const fields = computed<readonly Field[]>(() => [
  { name: 'delegate', label: t('handoffDelegate'), options: chains.value },
  { name: 'origin', label: t('handoffOrigin'), options: chains.value },
])

/* Two chains are needed for the check to mean anything — a trail handed off to
 * itself proves nothing. Said rather than hidden. */
const blockedReason = computed(() =>
  chains.value.length === 0 ? t('handoffNoChains') : undefined,
)

function run(values: Record<string, string>) {
  return runVerifyHandoff(values.delegate, values.origin)
}
</script>

<template>
  <PageHeader :title="t('handoffTitle')" :subtitle="t('handoffSub')" />
  <CommandForm :key="chains.length" :fields="fields" :run="run" :blocked-reason="blockedReason" />
</template>
