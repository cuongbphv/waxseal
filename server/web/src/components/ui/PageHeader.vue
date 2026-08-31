<script setup lang="ts">
/* The design's screen title: 24px semibold with a 13.5px muted line under it,
 * and an optional action rail on the right. */

withDefaults(
  defineProps<{
    title: string
    subtitle?: string
    /** The trail screen's h1 is the chain id, which is a hash-like token. */
    mono?: boolean
  }>(),
  { subtitle: undefined, mono: false },
)
</script>

<template>
  <header class="page-header">
    <div class="lede">
      <slot name="above" />
      <h1 :class="{ mono }">{{ title }}</h1>
      <p v-if="subtitle" class="sub">{{ subtitle }}</p>
      <slot name="below" />
    </div>
    <div v-if="$slots.actions" class="actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-8);
  flex-wrap: wrap;
}

.lede {
  min-width: 0;
}

h1 {
  font-size: var(--fs-h1);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-snug);
  line-height: var(--lh-tight);
  overflow-wrap: anywhere;
}

h1.mono {
  font-family: var(--font-mono);
}

.sub {
  margin-top: var(--space-2);
  font-size: var(--fs-md);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

.actions {
  display: flex;
  gap: var(--space-4);
  flex-wrap: wrap;
}
</style>
