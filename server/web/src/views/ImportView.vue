<script setup lang="ts">
/* Import: a real upload and a real list.
 *
 * An imported trail is evidence. The server stores it read-only and never
 * appends to it, which is why this is the one screen in the console that
 * writes anything at all — and what it writes is a file, never a chain entry.
 *
 * The entry count and the reason column come from running `report` against the
 * import, so both are the verifier's own words about the uploaded bytes rather
 * than a label this client invented for them.
 */

import { computed, ref } from 'vue'
import { useI18n } from '@/lib/i18n'
import { bytesLabel, countLabel, tsLabel } from '@/lib/format'
import { loadImportRows, uploadImport, type ImportRow } from '@/services/imports'
import { useAsyncData } from '@/composables/useAsyncData'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import DataTable from '@/components/ui/DataTable.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import StrokeIcon from '@/components/ui/StrokeIcon.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import VerdictBadge from '@/components/ui/VerdictBadge.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'

const { t } = useI18n()

const rows = useAsyncData<ImportRow[]>(() => loadImportRows())

const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref<string | null>(null)
const uploadError = ref<string | null>(null)
const dragging = ref(false)

async function send(file: File): Promise<void> {
  uploading.value = file.name
  uploadError.value = null
  try {
    await uploadImport(file)
    await rows.run()
  } catch (caught) {
    uploadError.value = caught instanceof Error ? caught.message : String(caught)
  } finally {
    uploading.value = null
  }
}

function onPick(event: Event): void {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) void send(file)
  input.value = ''
}

function onDrop(event: DragEvent): void {
  dragging.value = false
  const file = event.dataTransfer?.files?.[0]
  if (file) void send(file)
}

const columns = computed<Column[]>(() => [
  { key: 'name', label: t('colChain'), track: 'minmax(210px, 1.3fr)' },
  { key: 'entries', label: t('colEntries'), track: '110px' },
  { key: 'reason', label: t('colImportReason'), track: 'minmax(240px, 1.5fr)' },
  { key: 'verdict', label: t('colVerdict'), track: '150px', align: 'end' },
])

function reportOf(row: ImportRow) {
  return row.report.resolved ? row.report.value : null
}

/** The verifier's own reason for this file, and nothing else.
 *
 * `unverifiable_note` is boilerplate explaining what "unverifiable" means; it
 * is on the report whether or not any row was unverifiable, so printing it
 * unconditionally would put a finding in the cell of a clean trail. It appears
 * only when there are unverifiable seqs to explain. A blank reason under an
 * `ok` is the report saying nothing was wrong, and blank is what that should
 * look like. */
function reasonOf(row: ImportRow): string {
  const outcome = reportOf(row)
  if (!outcome) return row.report.resolved ? '' : row.report.error.code
  const body = outcome.report
  if (!body) return outcome.stderr.trim()
  if (body.chain.reason) return body.chain.reason
  return body.chain.unverifiable_seqs.length ? body.chain.unverifiable_note : ''
}
</script>

<template>
  <PageHeader :title="t('importTitle')" :subtitle="t('importSub')" />

  <AppCard>
    <div
      class="drop"
      :class="{ 'drop--over': dragging }"
      @dragover.prevent="dragging = true"
      @dragleave="dragging = false"
      @drop.prevent="onDrop"
    >
      <StrokeIcon name="upload" :size="36" :stroke="1.5" class="drop-icon" />
      <p class="drop-title">{{ t('dropTitle') }}</p>
      <p class="drop-sub">{{ t('dropSub') }}</p>
      <PillButton :disabled="!!uploading" @click="fileInput?.click()">
        {{ uploading ? t('importUploading', { name: uploading }) : t('chooseFile') }}
      </PillButton>
      <input ref="fileInput" class="sr-only" type="file" @change="onPick" />
    </div>
  </AppCard>

  <TintPanel v-if="uploadError" tone="broken" role="status">
    {{ t('importFailed', { detail: uploadError }) }}
  </TintPanel>

  <AsyncBlock
    :pending="rows.pending.value"
    :started="rows.started.value"
    :error="rows.error.value"
    @retry="rows.run"
  >
    <template #unauthorized><AuthNeeded /></template>

    <AppCard flush scroll-x>
      <div class="table-head">
        <h2>{{ t('imported') }}</h2>
      </div>
      <DataTable
        :columns="columns"
        :rows="rows.data.value ?? []"
        :row-key="(row) => row.record.import_id"
        min-width="var(--table-min-imports)"
      >
        <template #cell-name="{ row }">
          <div class="name mono truncate">{{ row.record.filename }}</div>
          <div class="src">
            {{ t('importSourceUpload', {
              at: tsLabel(row.record.imported_at),
              size: bytesLabel(row.record.size),
            }) }}
          </div>
        </template>

        <template #cell-entries="{ row }">
          <span v-if="reportOf(row)?.report">
            {{ countLabel(reportOf(row)!.report!.inventory.entries_total) }}
          </span>
          <span v-else class="muted-2" :title="t('notMeasuredWhy')">{{ t('notApplicable') }}</span>
        </template>

        <template #cell-reason="{ row }">
          <span class="mono reason truncate" :title="reasonOf(row)">{{ reasonOf(row) }}</span>
        </template>

        <template #cell-verdict="{ row }">
          <VerdictBadge v-if="reportOf(row)" :outcome="reportOf(row)!" />
          <span v-else class="muted-2">{{ t('serverSilent') }}</span>
        </template>

        <template #empty>{{ t('importNone') }}</template>
      </DataTable>
    </AppCard>
  </AsyncBlock>
</template>

<style scoped>
.drop {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-20) var(--space-10);
  border-radius: var(--radius-panel);
  border: var(--hairline) dashed transparent;
}

.drop--over {
  border-color: var(--color-primary);
  background: var(--tint-blue);
}

.drop-icon {
  color: var(--color-primary);
}

.drop-title {
  font-size: var(--fs-h4);
  font-weight: var(--fw-semibold);
}

.drop-sub {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  text-align: center;
}

.table-head {
  padding: var(--space-8) var(--card-pad-x);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
}

.table-head h2 {
  font-size: var(--fs-h4);
  font-weight: var(--fw-semibold);
}

.name {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.src {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-1);
}

.reason {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  display: block;
}
</style>
