<script setup lang="ts">
/* A state, rendered as the design's filled pill: the word and its exit code
 * inside a tinted lozenge.
 *
 * The word lives INSIDE the pill, which is why this shape rather than a bare
 * dot: strip the colour — greyscale, a colour-vision difference, a printed
 * page — and "unverifiable · 2" still says what it says. The tint is
 * reinforcement, never the message.
 *
 * One component, four tones. Verdicts and plain statuses share it because they
 * are the same object on screen; what differs is only which tone a caller
 * asks for.
 */

import type { Tone } from '@/lib/states'

withDefaults(
  defineProps<{
    tone: Tone
    /** The word. Required — there is no pill without one. */
    label: string
    /** The exit code, or any second token the design shows after the dot. */
    suffix?: string
    /** The sentence behind the pill. */
    title?: string
  }>(),
  { suffix: undefined, title: undefined },
)
</script>

<template>
  <span class="pill" :class="`pill--${tone}`" :title="title">
    <span>{{ label }}</span>
    <template v-if="suffix">
      <span class="sep" aria-hidden="true">·</span>
      <span class="mono suffix">{{ suffix }}</span>
    </template>
  </span>
</template>

<style scoped>
.pill {
  display: inline-flex;
  align-items: baseline;
  gap: var(--space-2);
  border-radius: var(--radius-pill);
  padding: var(--space-2) var(--space-6);
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
  white-space: nowrap;
  max-width: 100%;
}

.pill--ok {
  background: var(--status-tint-ok);
  color: var(--status-text-ok);
}

.pill--broken {
  background: var(--status-tint-broken);
  color: var(--status-text-broken);
}

.pill--unverifiable {
  background: var(--status-tint-unverifiable);
  color: var(--status-text-unverifiable);
}

.pill--neutral {
  background: var(--status-tint-neutral);
  color: var(--status-text-neutral);
}

.sep {
  opacity: 0.6;
}

.suffix {
  font-weight: var(--fw-semibold);
}
</style>
