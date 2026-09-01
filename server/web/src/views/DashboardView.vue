<script setup lang="ts">
/* The dashboard: four stat cards over the trails table.
 *
 * Every value here is read from the server. Three of the design's numbers had
 * to change shape to stay honest:
 *
 *   - `segments` is not one of the three reads a row makes — `loadChainOverview`
 *     fetches summary, verify and report — so the column renders the em dash
 *     with a `title` saying no count was taken. Workstream B shipped the
 *     command, which makes the dash a statement about this ROW rather than
 *     about the build. Never `1`: a segment count of one is a measurement, and
 *     nobody took it.
 *   - `dropped_writes` is `int | None`. `None` renders the WORD, and the
 *     aggregate says how many chains it could measure — a sum over a partial
 *     set presented as a total is the same collapse in a different place.
 *   - the design's "09:12 · 31/08" latest-anchor time is not in the report;
 *     `report.anchors` carries a check summary, not a timestamp. The card
 *     shows what was actually checked, or the word for nothing recorded.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'
import { bytesLabel, countLabel } from '@/lib/format'
import { checkSummary } from '@/lib/measure'
import { stateOf, type Tone } from '@/lib/states'
import { loadChainOverviews, type ChainOverview } from '@/services/chains'
import { valueOrNull } from '@/services/maybe'
import { useAsyncData } from '@/composables/useAsyncData'
import { useChainDirectory } from '@/composables/useChainDirectory'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import Badge from '@/components/ui/Badge.vue'
import DataTable from '@/components/ui/DataTable.vue'
import StatCard from '@/components/ui/StatCard.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import VerdictBadge from '@/components/ui/VerdictBadge.vue'
import TokenField from '@/components/app/TokenField.vue'
import ScopeStatement from '@/components/app/ScopeStatement.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const overviews = useAsyncData<ChainOverview[]>(
  async () => {
    await directory.reload()
    return loadChainOverviews(directory.ids.value ?? [])
  },
  { watching: [] },
)

const rows = computed(() => overviews.data.value ?? [])

/* ------------------------------------------------------------ stat cards */

/** The verdict breakdown, driven by `states.ts` rather than by a hard-coded
 * triple: a status this build has never seen still gets counted and named. */
const verdictCounts = computed(() => {
  const tally = new Map<string, { label: string; tone: Tone; count: number }>()
  for (const row of rows.value) {
    const outcome = valueOrNull(row.verify)
    const state = outcome ? stateOf(outcome.status) : stateOf('unavailable')
    const seen = tally.get(state.label)
    if (seen) seen.count += 1
    else tally.set(state.label, { label: state.label, tone: state.tone, count: 1 })
  }
  return [...tally.values()]
})

const drops = computed(() => {
  let total = 0
  let measured = 0
  for (const row of rows.value) {
    const completeness = valueOrNull(row.report)?.report?.completeness
    if (completeness?.dropped_writes != null) {
      total += completeness.dropped_writes
      measured += 1
    }
  }
  if (measured === 0) {
    return { value: t('notMeasured'), caption: t('statDropsNone'), title: t('notMeasuredWhy') }
  }
  return {
    value: `≥ ${total}`,
    caption:
      measured === rows.value.length
        ? t('statDrops')
        : t('statDropsPartial', { measured, total: rows.value.length }),
    title: t('statDrops'),
  }
})

const anchors = computed(() => {
  let checked = 0
  let recorded = 0
  for (const row of rows.value) {
    const summary = valueOrNull(row.report)?.report?.anchors
    if (summary) {
      checked += summary.checked
      recorded += 1
    }
  }
  if (recorded === 0) {
    return { value: t('notMeasured'), caption: t('statAnchorNone'), title: t('notMeasuredWhy') }
  }
  return {
    value: t('statAnchorChecked', { checked }),
    caption: t('sidecarAnchorsDesc'),
    title: t('sidecarAnchorsDesc'),
  }
})

/* ---------------------------------------------------------------- table */

const columns = computed<Column[]>(() => [
  { key: 'chain', label: t('colChain'), track: 'minmax(220px, 1.6fr)' },
  { key: 'segments', label: t('colSegments'), track: '84px' },
  { key: 'entries', label: t('colEntries'), track: '84px' },
  { key: 'size', label: t('colSize'), track: '84px' },
  { key: 'verdict', label: t('colVerdict'), track: '150px' },
  { key: 'anchor', label: t('colAnchor'), track: '160px', align: 'end' },
])

function summaryOf(row: ChainOverview) {
  return valueOrNull(row.summary)
}

function anchorCell(row: ChainOverview) {
  const report = valueOrNull(row.report)?.report
  if (!report) return { text: t('notMeasured'), title: t('notMeasuredWhy'), tone: 'neutral' as Tone }
  return checkSummary(report.anchors)
}
</script>

<template>
  <div class="stats">
    <StatCard
      :label="t('statChains')"
      :value="directory.count.value === null ? t('notMeasured') : countLabel(directory.count.value)"
      :caption="directory.count.value === null ? t('serverSilent') : t('statChainsSub', { count: directory.count.value })"
    />

    <StatCard :label="t('statVerdict')">
      <div class="verdicts">
        <span v-for="entry in verdictCounts" :key="entry.label" class="verdict-count">
          <span class="verdict-n" :class="`verdict-n--${entry.tone}`">{{ entry.count }}</span>
          <span class="verdict-word" :class="`verdict-n--${entry.tone}`">{{ entry.label }}</span>
        </span>
        <span v-if="!verdictCounts.length" class="muted">{{ t('nothingYet') }}</span>
      </div>
      <p class="thesis">{{ t('unverifiableWhy') }}</p>
    </StatCard>

    <StatCard
      :label="t('statDropsTitle')"
      :value="drops.value"
      :caption="drops.caption"
      :title="drops.title"
      :compact="drops.value === t('notMeasured')"
    />

    <StatCard
      :label="t('statAnchor')"
      :value="anchors.value"
      :caption="anchors.caption"
      :title="anchors.title"
      compact
    />
  </div>

  <AsyncBlock
    :pending="overviews.pending.value"
    :started="overviews.started.value"
    :error="overviews.error.value"
    @retry="overviews.run"
  >
    <template #unauthorized><TokenField /></template>

    <AppCard flush scroll-x>
      <div class="table-head">
        <h2>{{ t('trailsTitle') }}</h2>
      </div>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(row) => row.id"
        min-width="var(--table-min-trails)"
        :row-link="(row) => ({ name: 'trail', params: { id: row.id } })"
      >
        <template #cell-chain="{ row }">
          <div class="chain-name mono truncate">{{ row.id }}</div>
          <div class="chain-note">
            <template v-if="summaryOf(row)">
              <span v-if="summaryOf(row)!.head">{{ t('chainHead', { seq: summaryOf(row)!.head!.seq }) }}</span>
              <span v-else>{{ t('chainEmpty') }}</span>
            </template>
            <span v-else-if="!row.summary.resolved">
              {{ t('chainEntriesUnknown', { detail: row.summary.error.code }) }}
            </span>
          </div>
        </template>

        <template #cell-segments>
          <span class="muted-2" :title="t('segmentsNotCountedTitle')">{{ t('notApplicable') }}</span>
        </template>

        <template #cell-entries="{ row }">
          <span v-if="summaryOf(row)">{{ countLabel(summaryOf(row)!.entries) }}</span>
          <span v-else class="muted-2" :title="row.summary.resolved ? '' : row.summary.error.detail">
            {{ t('notApplicable') }}
          </span>
        </template>

        <template #cell-size="{ row }">
          <span v-if="summaryOf(row)">{{ bytesLabel(summaryOf(row)!.size_bytes) }}</span>
          <span v-else class="muted-2">{{ t('notApplicable') }}</span>
        </template>

        <template #cell-verdict="{ row }">
          <VerdictBadge v-if="row.verify.resolved" :outcome="row.verify.value" />
          <Badge v-else :title="row.verify.error.detail">{{ t('serverSilent') }}</Badge>
        </template>

        <!-- The anchors sidecar only. `.drops` is a different measurement and
             lives in its own card and its own sidecar row; stacking the two in
             one column invites reading one as the other. -->
        <template #cell-anchor="{ row }">
          <StatusPill
            :tone="anchorCell(row).tone"
            :label="anchorCell(row).text"
            :title="anchorCell(row).title"
          />
        </template>

        <template #empty>{{ t('noChains') }}</template>
      </DataTable>
    </AppCard>
  </AsyncBlock>

  <ScopeStatement form="statement" />
</template>

<style scoped>
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: var(--space-7);
}

.verdicts {
  display: flex;
  gap: var(--space-8);
  flex-wrap: wrap;
}

.verdict-count {
  display: flex;
  flex-direction: column;
}

.verdict-n {
  font-size: var(--fs-h2);
  font-weight: var(--fw-semibold);
  line-height: var(--lh-tight);
}

.verdict-word {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.verdict-n--ok {
  color: var(--status-text-ok);
}

.verdict-n--broken {
  color: var(--status-text-broken);
}

.verdict-n--unverifiable {
  color: var(--status-text-unverifiable);
}

.verdict-n--neutral {
  color: var(--status-text-neutral);
}

.thesis {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
}

.table-head {
  padding: var(--space-8) var(--card-pad-x);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
}

.table-head h2 {
  font-size: var(--fs-h3);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-nav);
}

.chain-name {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.chain-note {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-1);
}

.anchor-cell {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: var(--space-2);
  font-size: var(--fs-xs);
}
</style>
