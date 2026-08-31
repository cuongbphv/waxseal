<script setup lang="ts">
/* The design's small pale pill: a tier badge, an "imported" marker, a method
 * chip, a scope token. Text only — a badge never carries meaning in its tint
 * alone. */

withDefaults(
  defineProps<{
    tone?: 'neutral' | 'accent' | 'ok' | 'broken' | 'unverifiable'
    mono?: boolean
    /** The method chips in the endpoint table are a rectangle, not a pill. */
    shape?: 'pill' | 'square'
    title?: string
  }>(),
  { tone: 'neutral', mono: false, shape: 'pill', title: undefined },
)
</script>

<template>
  <span
    class="badge"
    :class="[`badge--${tone}`, `badge--${shape}`, { mono }]"
    :title="title"
  >
    <slot />
  </span>
</template>

<style scoped>
.badge {
  display: inline-block;
  font-size: var(--fs-xs);
  font-weight: var(--fw-semibold);
  padding: var(--space-1) var(--space-6);
  white-space: nowrap;
}

.badge--pill {
  border-radius: var(--radius-pill);
}

.badge--square {
  border-radius: var(--radius-badge);
  font-size: var(--fs-3xs);
  font-weight: var(--fw-bold);
  text-align: center;
  min-width: var(--space-20);
}

.badge--neutral {
  background: var(--tint-neutral);
  color: var(--color-ink-muted-48);
}

.badge--accent {
  background: var(--tint-blue);
  color: var(--color-primary);
}

.badge--ok {
  background: var(--status-tint-ok);
  color: var(--status-text-ok);
}

.badge--broken {
  background: var(--status-tint-broken);
  color: var(--status-text-broken);
}

.badge--unverifiable {
  background: var(--status-tint-unverifiable);
  color: var(--status-text-unverifiable);
}

.mono {
  font-family: var(--font-mono);
  font-weight: var(--fw-regular);
  font-size: var(--fs-4xs);
}
</style>
