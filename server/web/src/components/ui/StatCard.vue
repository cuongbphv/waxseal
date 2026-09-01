<script setup lang="ts">
/* The dashboard's stat tile.
 *
 * `value` is a string, not a number, on purpose: the honest value for an
 * unmeasured metric is a WORD ("not measured"), and a component typed to take
 * a number would force a caller to invent one. Rule 5 is easier to keep when
 * the type system does not push against it.
 */

import AppCard from './AppCard.vue'

withDefaults(
  defineProps<{
    label: string
    value?: string
    caption?: string
    /** Smaller value type, for a value that is a phrase rather than a count. */
    compact?: boolean
    title?: string
  }>(),
  { value: undefined, caption: undefined, compact: false, title: undefined },
)
</script>

<template>
  <AppCard>
    <div class="label">{{ label }}</div>
    <div v-if="value" class="value" :class="{ 'value--compact': compact }" :title="title">
      {{ value }}
    </div>
    <div v-else class="slot-value"><slot /></div>
    <div v-if="caption" class="caption">{{ caption }}</div>
  </AppCard>
</template>

<style scoped>
.label {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
}

.value {
  font-size: var(--fs-stat);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-tight);
  line-height: var(--lh-tight);
  margin-top: var(--space-2);
  overflow-wrap: anywhere;
}

.value--compact {
  font-size: var(--fs-h2);
  letter-spacing: var(--ls-nav);
  margin-top: var(--space-5);
}

.slot-value {
  margin-top: var(--space-6);
}

.caption {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-2);
  line-height: var(--lh-body);
}
</style>
