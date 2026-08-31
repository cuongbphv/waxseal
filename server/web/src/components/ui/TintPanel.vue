<script setup lang="ts">
/* The design's tinted strip: a pale ground, a tone, and prose.
 *
 * It carries the verdict banner on the trail screen and every "this build has
 * not measured that" notice. Both are the same object — a statement about
 * evidence, tinted by how strong the statement is — so they are one component.
 * The neutral tone is not a weaker red: it is the ground for "no measurement
 * was taken", which is not a finding at all.
 */

import type { Tone } from '@/lib/states'

withDefaults(
  defineProps<{
    tone?: Tone
    title?: string
    /** Render as a note rather than an alert; alerts are announced. */
    role?: 'note' | 'status'
  }>(),
  { tone: 'neutral', title: undefined, role: 'note' },
)
</script>

<template>
  <div class="tint" :class="`tint--${tone}`" :role="role === 'status' ? 'status' : undefined">
    <div v-if="title" class="tint-title">{{ title }}</div>
    <div class="tint-body"><slot /></div>
    <slot name="aside" />
  </div>
</template>

<style scoped>
.tint {
  border-radius: var(--radius-panel);
  padding: var(--space-7) var(--card-pad-x);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.tint--ok {
  background: var(--status-tint-ok);
}

.tint--broken {
  background: var(--status-tint-broken);
}

.tint--unverifiable {
  background: var(--status-tint-unverifiable);
}

.tint--neutral {
  background: var(--tint-blue);
  border: var(--hairline) solid var(--tint-blue-border);
}

.tint-title {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
}

.tint--ok .tint-title {
  color: var(--status-text-ok);
}

.tint--broken .tint-title {
  color: var(--status-text-broken);
}

.tint--unverifiable .tint-title {
  color: var(--status-text-unverifiable);
}

.tint--neutral .tint-title {
  color: var(--color-primary);
}

.tint-body {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

.tint-body:empty {
  display: none;
}
</style>
