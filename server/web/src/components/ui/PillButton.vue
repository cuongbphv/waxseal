<script setup lang="ts">
/* The design's pill control, in its three forms: filled, outlined and the
 * dark tab. There is exactly one accent colour and this is where it lives.
 *
 * Status colours never appear here. A verdict is not a thing to click, and a
 * red button reads as "do the dangerous thing" rather than "a break was
 * found".
 */

withDefaults(
  defineProps<{
    variant?: 'primary' | 'outline' | 'tab'
    active?: boolean
    disabled?: boolean
    title?: string
    type?: 'button' | 'submit'
  }>(),
  { variant: 'primary', active: false, disabled: false, title: undefined, type: 'button' },
)
</script>

<template>
  <button
    :type="type"
    :class="['pill', `pill--${variant}`, { 'pill--active': active }]"
    :disabled="disabled"
    :title="title"
    :aria-pressed="variant === 'tab' ? active : undefined"
  >
    <slot />
  </button>
</template>

<style scoped>
.pill {
  cursor: pointer;
  border-radius: var(--radius-pill);
  font-size: var(--fs-base);
  font-weight: var(--fw-medium);
  border: var(--hairline) solid transparent;
  background: transparent;
  transition: transform 0.1s ease;
}

.pill:active:not(:disabled) {
  transform: scale(var(--press-scale));
}

.pill:disabled {
  cursor: not-allowed;
  opacity: 0.45;
}

.pill--primary {
  padding: var(--space-5) var(--space-10);
  background: var(--color-primary);
  color: var(--color-on-primary);
}

.pill--outline {
  padding: var(--space-5) var(--space-10);
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.pill--tab {
  padding: var(--space-4) var(--space-8);
  color: var(--color-ink-muted-48);
  font-weight: var(--fw-regular);
}

.pill--tab:hover {
  color: var(--color-ink);
}

.pill--tab.pill--active {
  background: var(--color-surface-ink);
  color: var(--color-on-dark);
  font-weight: var(--fw-semibold);
}
</style>
