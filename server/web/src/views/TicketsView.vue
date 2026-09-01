<script setup lang="ts">
/* `reconcile-tickets` — D2's exogenous admission tickets.
 *
 * The three-valued answer is the whole point, so it gets its own panel above
 * the raw output: a missing ticket is a POSITIVELY DETECTED drop, while no
 * issuer data is "unmeasured". Rendering the second as "0 drops" is the one
 * thing this command exists to prevent, so `measured: false` shows as its own
 * state and `missing` stays blank rather than becoming a zero.
 */

import { computed, ref } from 'vue'
import { useI18n } from '@/lib/i18n'
import { runReconcileTickets } from '@/services/chains'
import { useChainDirectory } from '@/composables/useChainDirectory'
import type { Outcome, Reconciliation } from '@/lib/api'
import PageHeader from '@/components/ui/PageHeader.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import CommandForm, { type Field } from '@/components/app/CommandForm.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const chains = computed(() => directory.ids.value ?? [])
const reconciliation = ref<Reconciliation | null>(null)

const fields = computed<readonly Field[]>(() => [
  { name: 'chain', label: t('ticketsChain'), options: chains.value },
  { name: 'issuer', label: t('ticketsIssuer'), placeholder: 'acme' },
  { name: 'lease_size', label: t('ticketsLease'), placeholder: '10' },
  { name: 'issued', label: t('ticketsIssued'), placeholder: '1-10', optional: true },
])

const blockedReason = computed(() =>
  chains.value.length === 0 ? t('ticketsNoChains') : undefined,
)

async function run(values: Record<string, string>): Promise<Outcome> {
  const outcome = await runReconcileTickets(
    values.chain,
    values.issuer,
    values.lease_size,
    values.issued || undefined,
  )
  reconciliation.value = outcome.reconciliation
  return outcome
}

/* Three states, never two. `measured: false` is not a weaker "no drops". */
const summary = computed(() => {
  const r = reconciliation.value
  if (r === null) return null
  if (!r.measured) return { tone: 'unverifiable' as const, title: t('ticketsUnmeasured') }
  const missing = r.missing ?? []
  return missing.length
    ? { tone: 'broken' as const, title: t('ticketsDropped', { n: missing.length }) }
    : { tone: 'ok' as const, title: t('ticketsNoDrops') }
})
</script>

<template>
  <PageHeader :title="t('ticketsTitle')" :subtitle="t('ticketsSub')" />

  <TintPanel v-if="summary" :tone="summary.tone" :title="summary.title" role="status">
    <template v-if="reconciliation">
      {{
        t('ticketsBlindSpot', {
          bound: reconciliation.blind_spot_bound,
          lease: reconciliation.lease_size,
        })
      }}
    </template>
  </TintPanel>

  <CommandForm :key="chains.length" :fields="fields" :run="run" :blocked-reason="blockedReason" />
</template>
