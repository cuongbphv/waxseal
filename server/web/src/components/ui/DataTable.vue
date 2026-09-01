<script setup lang="ts" generic="Row">
/* The design's table: a hairline-separated grid inside a card, with the header
 * strip and every row sharing one track list.
 *
 * Rows can be links (the dashboard opens a trail) or inert (everything else).
 * No row mutates a chain, here or anywhere — the console never appends, edits
 * or repairs an entry. The one control a row may carry is the API keys screen's
 * Revoke, which withdraws a credential and touches no trail.
 */

import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { trackList, type Column } from './table'

const props = withDefaults(
  defineProps<{
    columns: readonly Column[]
    rows: readonly Row[]
    rowKey: (row: Row, index: number) => string
    /** Below this the table scrolls inside its card, per the design. */
    minWidth?: string
    /** Return a route to make the row a link, or null to leave it inert. */
    rowLink?: (row: Row) => RouteLocationRaw | null
    /** Tint the row's ground — the design shades the genesis entry. */
    rowTint?: (row: Row) => boolean
  }>(),
  { minWidth: undefined, rowLink: undefined, rowTint: undefined },
)

const tracks = computed(() => trackList(props.columns))
const gridStyle = computed(() => ({
  gridTemplateColumns: tracks.value,
  minWidth: props.minWidth,
}))
</script>

<template>
  <div class="table" role="table">
    <div class="head" role="row" :style="gridStyle">
      <div
        v-for="column in columns"
        :key="column.key"
        role="columnheader"
        :class="['cell', `cell--${column.align ?? 'start'}`]"
      >
        {{ column.label }}
      </div>
    </div>

    <component
      :is="rowLink?.(row) ? 'RouterLink' : 'div'"
      v-for="(row, index) in rows"
      :key="rowKey(row, index)"
      :to="rowLink?.(row) ?? undefined"
      role="row"
      class="row"
      :class="{ 'row--link': !!rowLink?.(row), 'row--tint': rowTint?.(row) }"
      :style="gridStyle"
    >
      <div
        v-for="column in columns"
        :key="column.key"
        role="cell"
        :class="['cell', `cell--${column.align ?? 'start'}`]"
      >
        <slot :name="`cell-${column.key}`" :row="row" :index="index" />
      </div>
    </component>

    <div v-if="!rows.length" class="empty">
      <slot name="empty" />
    </div>

    <div v-if="$slots.foot" class="foot">
      <slot name="foot" />
    </div>
  </div>
</template>

<style scoped>
.table {
  display: flex;
  flex-direction: column;
}

.head,
.row {
  display: grid;
  gap: 0 var(--space-7);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
}

.head {
  padding: var(--space-4) var(--card-pad-x);
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
}

.row {
  align-items: center;
  padding: var(--row-pad-y) var(--card-pad-x);
  color: inherit;
}

.row--tint {
  background: var(--color-surface-pearl);
}

.row--link {
  text-decoration: none;
  cursor: pointer;
}

.row--link:hover {
  background: var(--color-surface-pearl);
  text-decoration: none;
}

.cell {
  min-width: 0;
}

.cell--end {
  text-align: right;
  justify-self: end;
}

.empty,
.foot {
  padding: var(--space-6) var(--card-pad-x);
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
