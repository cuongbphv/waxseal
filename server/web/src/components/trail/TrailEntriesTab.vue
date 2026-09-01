<script setup lang="ts">
/* The chain's entries, in write order.
 *
 * The design's mock has a `redactPayloads` toggle. There is no such control
 * here and there cannot be one: redaction runs BEFORE `payload_hash` is
 * computed, so the cleartext never reached this server and there is nothing
 * for a toggle to reveal. The footer says so rather than leaving the absence
 * to be noticed.
 */

import { computed } from 'vue'
import type { DisplayEntry } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { decodePayload, oneLine, tsLabel } from '@/lib/format'
import { loadEntryWindow, type EntryWindow } from '@/services/chains'
import { useAsyncData } from '@/composables/useAsyncData'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import DataTable from '@/components/ui/DataTable.vue'
import HashValue from '@/components/ui/HashValue.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'

const props = defineProps<{ chainId: string }>()

const { t } = useI18n()

const window = useAsyncData<EntryWindow>(() => loadEntryWindow(props.chainId), {
  watching: [() => props.chainId],
})

const columns = computed<Column[]>(() => [
  { key: 'seq', label: 'seq', track: '60px' },
  { key: 'ts', label: t('colTs'), track: '150px' },
  { key: 'type', label: t('colPayloadType'), track: 'minmax(190px, 1.1fr)' },
  { key: 'payload', label: t('colPayload'), track: 'minmax(220px, 1.6fr)' },
  { key: 'hash', label: t('colEntryHash'), track: '130px', align: 'end' },
])

const entries = computed(() => window.data.value?.entries ?? [])

/** Bytes that are not UTF-8 are not text; saying so beats rendering
 * replacement characters that look like content. */
function payloadOf(entry: DisplayEntry): { text: string; title: string } {
  const decoded = decodePayload(entry.payload_b64)
  if (decoded === null) {
    return { text: t('notApplicable'), title: `${entry.payload_b64.length} base64 chars` }
  }
  return { text: oneLine(decoded), title: decoded }
}

/* Genesis carries prev_hash = 64 zeros, and the design tints its row. */
function isGenesis(entry: DisplayEntry): boolean {
  return entry.header.seq === 0
}
</script>

<template>
  <AsyncBlock
    :pending="window.pending.value"
    :started="window.started.value"
    :error="window.error.value"
    @retry="window.run"
  >
    <template #unauthorized><AuthNeeded /></template>

    <AppCard flush scroll-x>
      <DataTable
        :columns="columns"
        :rows="entries"
        :row-key="(entry) => String(entry.header.seq)"
        min-width="var(--table-min-entries)"
        :row-tint="isGenesis"
      >
        <template #cell-seq="{ row }">
          <span class="seq mono">{{ row.header.seq }}</span>
        </template>
        <template #cell-ts="{ row }">
          <span class="mono dim" :title="row.header.ts">{{ tsLabel(row.header.ts) }}</span>
        </template>
        <template #cell-type="{ row }">
          <span class="mono dim truncate" :title="row.header.payload_type">
            {{ row.header.payload_type }}
          </span>
        </template>
        <template #cell-payload="{ row }">
          <span class="mono payload truncate" :title="payloadOf(row).title">
            {{ payloadOf(row).text }}
          </span>
        </template>
        <template #cell-hash="{ row }">
          <HashValue :value="row.entry_hash" tone="link" copyable />
        </template>

        <template #empty>{{ t('entriesEmpty') }}</template>

        <template #foot>
          <p>{{ t('entriesFoot') }}</p>
          <p class="why">{{ t('entriesFootWhy') }}</p>
          <p v-if="window.data.value?.truncated" class="why">
            {{ t('entriesMore', { shown: entries.length }) }}
          </p>
        </template>
      </DataTable>
    </AppCard>
  </AsyncBlock>
</template>

<style scoped>
.seq {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.dim {
  font-size: var(--fs-2xs);
  color: var(--color-ink-muted-48);
}

.payload {
  font-size: var(--fs-2xs);
  display: block;
}

.why {
  margin-top: var(--space-2);
  color: var(--color-ink-muted-2);
}
</style>
