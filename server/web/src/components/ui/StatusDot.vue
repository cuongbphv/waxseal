<script setup lang="ts">
/* A status, carried by a word first and a colour second.
 *
 * The dot alone is never the message: `label` renders beside it, or — where
 * the design shows only the dot — is exposed to assistive tech and to a
 * `title`. A screen read in greyscale, or by someone who cannot distinguish
 * the green from the orange, still says which of the states it is in.
 */

import type { Tone } from '@/lib/states'

withDefaults(
  defineProps<{
    tone: Tone
    /** The word. Required: there is no dot without one. */
    label: string
    /** The sentence behind the word, for the `title`. */
    title?: string
    /** Hide the word visually — it stays in the accessible name and the title.
     * Only for the cells where the design has no room for it. */
    labelHidden?: boolean
    size?: 'sm' | 'md'
  }>(),
  { title: undefined, labelHidden: false, size: 'md' },
)
</script>

<template>
  <span class="dot-row" :title="title ?? label">
    <span class="dot" :class="[`dot--${tone}`, `dot--${size}`]" aria-hidden="true" />
    <span :class="labelHidden ? 'sr-only' : 'dot-label'">{{ label }}</span>
    <slot />
  </span>
</template>

<style scoped>
.dot-row {
  display: inline-flex;
  align-items: center;
  gap: var(--space-3);
  white-space: nowrap;
}

.dot {
  border-radius: var(--radius-circle);
  flex-shrink: 0;
}

.dot--md {
  width: var(--dot-size);
  height: var(--dot-size);
}

.dot--sm {
  width: var(--dot-size-sm);
  height: var(--dot-size-sm);
}

.dot--ok {
  background: var(--status-dot-ok);
}

.dot--broken {
  background: var(--status-dot-broken);
}

.dot--unverifiable {
  background: var(--status-dot-unverifiable);
}

.dot--neutral {
  background: var(--status-dot-neutral);
}

.dot-label {
  font-size: var(--fs-2xs);
  color: var(--color-ink-muted-48);
}
</style>
