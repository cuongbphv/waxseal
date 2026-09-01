<script setup lang="ts">
/* A hash, shown short and reachable in full.
 *
 * A truncated hash an operator cannot expand is not evidence of anything, so
 * the full value is always in the `title` and always on the clipboard button.
 */

import { computed, ref } from 'vue'
import { HASH_SHORT_CHARS } from '@/lib/constants'
import { shortHash } from '@/lib/format'

const props = withDefaults(
  defineProps<{
    value: string
    chars?: number
    copyable?: boolean
    tone?: 'link' | 'ink' | 'muted'
  }>(),
  { chars: HASH_SHORT_CHARS, copyable: false, tone: 'ink' },
)

const copied = ref(false)
const display = computed(() => shortHash(props.value, props.chars))

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    window.setTimeout(() => (copied.value = false), 1200)
  } catch {
    /* Clipboard access can be refused; the `title` still carries the value. */
  }
}
</script>

<template>
  <span class="hash">
    <span class="mono" :class="`hash--${tone}`" :title="value">{{ display }}</span>
    <button v-if="copyable" type="button" class="copy" :title="value" @click="copy">
      {{ copied ? '✓' : '⧉' }}
    </button>
  </span>
</template>

<style scoped>
.hash {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  min-width: 0;
}

.hash--link {
  color: var(--color-primary);
}

.hash--muted {
  color: var(--color-ink-muted-48);
}

.hash--ink {
  color: var(--color-ink);
}

.mono {
  font-size: var(--fs-3xs);
  overflow: hidden;
  text-overflow: ellipsis;
}

.copy {
  border: 0;
  background: transparent;
  cursor: pointer;
  color: var(--color-ink-muted-2);
  padding: 0 var(--space-1);
  font-size: var(--fs-3xs);
}

.copy:hover {
  color: var(--color-primary);
}
</style>
