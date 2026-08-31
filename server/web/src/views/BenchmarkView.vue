<script setup lang="ts">
/* Benchmark: four published figures, labelled as published.
 *
 * The numbers are real — they are the ones recorded in the 0.1.5 CHANGELOG for
 * the reference workload, each with a falsifiability receipt behind it. What
 * they are not is a measurement of THIS deployment: this server does not
 * benchmark itself and has measured nothing here. The panel above says so, and
 * every row carries the source, because a bar chart on a console reads as
 * "your system" unless it is told otherwise.
 */

import { useI18n } from '@/lib/i18n'
import {
  BENCHMARKS,
  BENCHMARK_AFTER_VERSION,
  BENCHMARK_BEFORE_VERSION,
  BENCHMARK_SOURCE,
} from '@/content'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()
</script>

<template>
  <PageHeader :title="t('benchTitle')" :subtitle="t('benchSub')" />

  <TintPanel :title="t('benchPublishedTitle')">{{ t('benchPublishedBody') }}</TintPanel>

  <ul class="rows">
    <li v-for="row in BENCHMARKS" :key="row.nameKey">
      <AppCard size="panel">
        <div class="head">
          <h2>{{ t(row.nameKey) }}</h2>
          <span class="delta mono">{{ row.delta ?? t(row.deltaKey!) }}</span>
        </div>
        <div class="bars">
          <div class="bar-row">
            <span class="version">{{ BENCHMARK_BEFORE_VERSION }}</span>
            <span class="track"><span class="fill fill--before" :style="{ width: row.beforeWidth }" /></span>
            <span class="value mono">{{ row.before }}</span>
          </div>
          <div class="bar-row">
            <span class="version">{{ BENCHMARK_AFTER_VERSION }}</span>
            <span class="track"><span class="fill fill--after" :style="{ width: row.afterWidth }" /></span>
            <span class="value mono value--after">{{ row.after }}</span>
          </div>
        </div>
        <Badge class="source" mono>{{ BENCHMARK_SOURCE }}</Badge>
      </AppCard>
    </li>
  </ul>

  <p class="foot">{{ t('benchFoot') }}</p>
</template>

<style scoped>
.rows {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

.head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--space-6);
  flex-wrap: wrap;
}

h2 {
  font-size: var(--fs-md);
  font-weight: var(--fw-semibold);
}

.delta {
  font-size: var(--fs-xs);
  font-weight: var(--fw-semibold);
  color: var(--color-text-affirm);
}

.bars {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  margin-top: var(--space-6);
}

.bar-row {
  display: flex;
  align-items: center;
  gap: var(--space-5);
}

.version {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  width: 44px;
  flex-shrink: 0;
}

.track {
  flex: 1;
  height: var(--space-4);
  background: var(--color-canvas-parchment);
  border-radius: var(--radius-pill);
  overflow: hidden;
}

.fill {
  display: block;
  height: 100%;
  border-radius: var(--radius-pill);
}

.fill--before {
  background: var(--color-surface-chip-translucent);
}

.fill--after {
  background: var(--color-primary);
}

.value {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  width: 110px;
  text-align: right;
  flex-shrink: 0;
}

.value--after {
  color: var(--color-primary);
}

.source {
  margin-top: var(--space-6);
}

.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
