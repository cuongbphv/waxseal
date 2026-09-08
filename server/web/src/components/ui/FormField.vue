<script setup lang="ts">
/* One labelled control. Users, Keys, and CommandForm used to each spell the
 * same field chrome; a third copy would be a third place for the focus ring
 * to drift. The input itself is the slot — this does not own the value.
 */

defineProps<{
  label: string
  hint?: string
  narrow?: boolean
}>()
</script>

<template>
  <label class="field" :class="{ 'field--narrow': narrow }">
    <span class="label"><slot name="label">{{ label }}</slot></span>
    <slot />
    <span v-if="hint" class="hint">{{ hint }}</span>
  </label>
</template>

<style scoped>
.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  min-width: 0;
}

.field--narrow {
  max-width: 320px;
}

.label {
  font-size: var(--fs-3xs);
  font-family: var(--font-mono);
  color: var(--color-ink-muted-2);
}

.hint {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

:deep(.input) {
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--color-hairline);
  background: var(--color-surface-pearl);
  outline: none;
  min-width: 0;
}

:deep(.input:focus) {
  border-color: var(--color-primary-focus);
}
</style>
