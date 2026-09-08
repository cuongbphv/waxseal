<script setup lang="ts">
/* The receipt chain across every chain the server holds, newest first, plus
 * both verdicts side by side.
 *
 * Both, because they answer different questions and only one of them catches
 * the interesting attack. `verify` asks whether the acknowledgment log is
 * internally consistent — it stays `ok` after an edit to the trail, because
 * the log itself was not touched. `cross-check` asks whether entry `seq` still
 * carries the hash acknowledged for it, which is what catches a
 * self-consistent local rewrite. Showing one and labelling it "receipts" would
 * answer the easy question under the hard question's name.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'
import { tsLabel } from '@/lib/format'
import { loadReceiptFeed, type ReceiptFeed } from '@/services/receipts'
import { panelsByChainId } from '@/lib/receiptPresentation'
import { useAsyncData } from '@/composables/useAsyncData'
import { useChainDirectory } from '@/composables/useChainDirectory'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import DataTable from '@/components/ui/DataTable.vue'
import HashValue from '@/components/ui/HashValue.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusPill from '@/components/ui/StatusPill.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const feed = useAsyncData<ReceiptFeed>(async () => {
  await directory.reload()
  return loadReceiptFeed(directory.ids.value ?? [])
})

const columns = computed<Column[]>(() => [
  { key: 'index', label: t('colReceiptIndex'), track: '64px' },
  { key: 'ts', label: t('colTs'), track: '150px' },
  { key: 'chain', label: t('colChain'), track: 'minmax(190px, 1.2fr)' },
  { key: 'seq', label: 'seq', track: '100px' },
  { key: 'head', label: t('colRunningHead'), track: 'minmax(170px, 1fr)', align: 'end' },
])

const records = computed(() => feed.data.value?.records ?? [])
const checks = computed(() => feed.data.value?.checks ?? [])
const panels = computed(() => panelsByChainId(checks.value, t))
</script>

<template>
  <PageHeader :title="t('receiptsTitle')" :subtitle="t('receiptsSub')" />

  <AsyncBlock
    :pending="feed.pending.value"
    :started="feed.started.value"
    :error="feed.error.value"
    @retry="feed.run"
  >
    <AppCard flush scroll-x>
      <DataTable
        :columns="columns"
        :rows="records"
        :row-key="(record) => `${record.chainId}:${record.receipt_seq}`"
        min-width="var(--table-min-receipts)"
      >
        <template #cell-index="{ row }">
          <span class="mono strong">{{ row.receipt_seq }}</span>
        </template>
        <template #cell-ts="{ row }">
          <span class="mono dim" :title="row.ts">{{ tsLabel(row.ts) }}</span>
        </template>
        <template #cell-chain="{ row }">
          <span class="mono truncate">{{ row.chainId }}</span>
        </template>
        <template #cell-seq="{ row }">
          <span class="mono">{{ row.seq }}</span>
        </template>
        <template #cell-head="{ row }">
          <HashValue :value="row.receipt_head" tone="link" copyable />
        </template>

        <template #empty>{{ t('receiptsNone') }}</template>

        <template #foot>{{ t('receiptsFoot') }}</template>
      </DataTable>
    </AppCard>

    <section v-for="entry in checks" :key="entry.chainId" class="checks">
      <h2 class="chain mono">{{ entry.chainId }}</h2>
      <div class="pair">
        <AppCard size="panel">
          <h3 class="q-title mono">{{ t('receiptsVerifyTitle') }}</h3>
          <p class="q">{{ t('receiptsVerifyQuestion') }}</p>
          <StatusPill
            :tone="panels.get(entry.chainId)!.verify.tone"
            :label="panels.get(entry.chainId)!.verify.label"
            :title="panels.get(entry.chainId)!.verify.title"
          />
        </AppCard>
        <AppCard size="panel">
          <h3 class="q-title mono">{{ t('receiptsCrossTitle') }}</h3>
          <p class="q">{{ t('receiptsCrossQuestion') }}</p>
          <StatusPill
            :tone="panels.get(entry.chainId)!.cross.tone"
            :label="panels.get(entry.chainId)!.cross.label"
            :title="panels.get(entry.chainId)!.cross.title"
          />
        </AppCard>
      </div>
    </section>
  </AsyncBlock>
</template>

<style scoped>
.strong {
  font-weight: var(--fw-semibold);
  font-size: var(--fs-xs);
}

.dim {
  font-size: var(--fs-2xs);
  color: var(--color-ink-muted-48);
}

.checks {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  margin-top: var(--content-gap);
}

.chain {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
  color: var(--color-ink-muted-48);
}

.pair {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--space-6);
}

.q-title {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
}

.q {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin: var(--space-2) 0 var(--space-6);
  line-height: var(--lh-body);
}
</style>
