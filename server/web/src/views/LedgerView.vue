<script setup lang="ts">
/* Ledger status — the real reading when it is configured, and a state when not.
 *
 * This screen used to be static: the contracts were real design but their
 * status was never queried, because there was nowhere to put an RPC endpoint.
 * Settings holds those now, so the reading here comes from `ledger-status`.
 *
 * What has NOT changed is what happens when nothing is configured. That is
 * reported as a state naming the setting that would fix it — never "live", and
 * never a green dot borrowed from a chain nobody queried.
 */

import { computed, watch } from 'vue'
import { useI18n } from '@/lib/i18n'
import { loadLedgerStatus } from '@/services/ledger'
import { LEDGER_CONTRACTS } from '@/content'
import { useAsyncData } from '@/composables/useAsyncData'
import { useChainDirectory } from '@/composables/useChainDirectory'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import OutputPanel from '@/components/ui/OutputPanel.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import VerdictBadge from '@/components/ui/VerdictBadge.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'

const { t } = useI18n()
const directory = useChainDirectory()

/* Per-chain, because the on-chain status is about one trail's anchors. */
const chain = computed(() => directory.ids.value?.[0] ?? null)

const status = useAsyncData(() => {
  const id = chain.value
  if (id === null) throw new Error('no chain')
  return loadLedgerStatus(id)
})

watch(chain, (id) => {
  if (id !== null) void status.run()
})

const configured = computed(() => status.data.value?.configured === true)
const missing = computed(() => status.data.value?.missing ?? [])
</script>

<template>
  <PageHeader :title="t('ledgerTitle')" :subtitle="t('ledgerSub')" />

  <TintPanel v-if="chain === null" :title="t('ledgerNoChain')" />

  <template v-else>
    <AsyncBlock
      :pending="status.pending.value"
      :started="status.started.value"
      :error="status.error.value"
      @retry="status.run"
    >
      <template #unauthorized><AuthNeeded /></template>

      <!-- Not configured is a STATE, and it names the setting that fixes it. -->
      <TintPanel
        v-if="status.data.value && !configured"
        :title="t('ledgerNotConfigured')"
        role="status"
      >
        {{ t('ledgerMissing', { keys: missing.join(', ') }) }}
      </TintPanel>

      <template v-if="configured && status.data.value?.outcome">
        <VerdictBadge :outcome="status.data.value.outcome" />
        <OutputPanel
          :argv="status.data.value.outcome.argv"
          :stdout="status.data.value.outcome.stdout"
          :stderr="status.data.value.outcome.stderr"
          :exit-code="status.data.value.outcome.exit_code"
        />
      </template>
    </AsyncBlock>
  </template>

  <div class="grid">
    <AppCard v-for="contract in LEDGER_CONTRACTS" :key="contract.nameKey">
      <div class="head">
        <h2>{{ t(contract.nameKey) }}</h2>
        <StatusPill
          :tone="configured ? 'ok' : 'neutral'"
          :label="t(configured ? 'ledgerQueried' : 'notConfigured')"
          :title="t(configured ? 'ledgerQueriedWhy' : 'ledgerUnavailableBody')"
        />
      </div>
      <p class="desc">{{ t(contract.descriptionKey) }}</p>
    </AppCard>
  </div>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: var(--space-6);
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  flex-wrap: wrap;
}

h2 {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-nav);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
  line-height: var(--lh-body);
}
</style>
