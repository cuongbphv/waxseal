<script setup lang="ts">
/* One sidecar, in the design's two-up card grid.
 *
 * `null` renders "not recorded" with the NEUTRAL tone, never the green one.
 * A sidecar that was never written and a sidecar that was written and checked
 * clean are opposite claims, and the green dot is the one that says a check
 * happened.
 */

import type { Measurement } from '@/lib/measure'
import AppCard from '@/components/ui/AppCard.vue'
import StatusPill from '@/components/ui/StatusPill.vue'

defineProps<{
  name: string
  description: string
  status: Measurement
}>()
</script>

<template>
  <AppCard size="panel">
    <div class="row">
      <div class="text">
        <div class="name mono">{{ name }}</div>
        <p class="desc">{{ description }}</p>
        <slot />
      </div>
      <StatusPill :tone="status.tone" :label="status.text" :title="status.title" />
    </div>
  </AppCard>
</template>

<style scoped>
.row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-6);
}

.text {
  min-width: 0;
}

.name {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-1);
  line-height: var(--lh-body);
}
</style>
