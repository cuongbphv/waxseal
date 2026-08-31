<script setup lang="ts">
/* The design's one surface: white, hairline, 18px radius (14px for the
 * secondary size). Every panel in the portal is this, so it is one component
 * and not eleven copies of the same four declarations. */

withDefaults(
  defineProps<{
    /** `card` is the 18px surface; `panel` is the 14px one the design uses for
     * rows in a stack (tiers, segments, sidecars). */
    size?: 'card' | 'panel'
    /** Padding off, for cards that own a table or a header strip. */
    flush?: boolean
    /** Let a wide child scroll inside the card rather than the page. */
    scrollX?: boolean
  }>(),
  { size: 'card', flush: false, scrollX: false },
)
</script>

<template>
  <div
    class="card"
    :class="[`card--${size}`, { 'card--flush': flush, 'card--scroll': scrollX }]"
  >
    <slot />
  </div>
</template>

<style scoped>
.card {
  background: var(--color-canvas);
  border: var(--hairline) solid var(--color-hairline);
  min-width: 0;
}

.card--card {
  border-radius: var(--radius-card);
  padding: var(--card-pad-y) var(--card-pad-x);
}

.card--panel {
  border-radius: var(--radius-panel);
  padding: var(--space-7) var(--card-pad-x);
}

.card--flush {
  padding: 0;
}

.card--scroll {
  overflow-x: auto;
}
</style>
