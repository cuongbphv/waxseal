<script setup lang="ts">
/* Pending, failed-with-reason, or loaded — rendered as three visibly different
 * things.
 *
 * The failure mode this exists to prevent is an empty table drawn over a
 * failed request: it reads as "nothing here", which is a claim the request
 * never supported. A 401 gets its own slot because "supply a credential" is a
 * different instruction to the operator than "the request failed".
 */

import type { ApiError } from '@/lib/api'
import { useI18n } from '@/lib/i18n'

defineProps<{
  pending: boolean
  started: boolean
  error: ApiError | null
}>()

defineEmits<{ retry: [] }>()

const { t } = useI18n()
</script>

<template>
  <!-- Pending wins over the default slot, always. Rendering the slot while a
       request is in flight draws an empty table over a request that has not
       answered yet, which reads as "nothing here" — the exact claim this
       component exists to refuse to make. -->
  <div v-if="!started || pending" class="state" role="status">
    {{ t('loading') }}
  </div>
  <div v-else-if="error && error.isUnauthorized" class="state">
    <slot name="unauthorized">
      <span>{{ t('authNeeded') }}</span>
    </slot>
  </div>
  <div v-else-if="error" class="state state--error" role="status">
    <span>{{ t('loadFailed', { detail: error.detail || error.code }) }}</span>
    <button type="button" class="retry" @click="$emit('retry')">{{ t('retry') }}</button>
  </div>
  <slot v-else />
</template>

<style scoped>
.state {
  display: flex;
  align-items: center;
  gap: var(--space-6);
  flex-wrap: wrap;
  padding: var(--space-7) var(--card-pad-x);
  background: var(--color-canvas);
  border: var(--hairline) solid var(--color-hairline);
  border-radius: var(--radius-panel);
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
}

.state--error {
  color: var(--status-text-broken);
}

.retry {
  border: var(--hairline) solid var(--color-primary);
  background: transparent;
  color: var(--color-primary);
  border-radius: var(--radius-pill);
  padding: var(--space-2) var(--space-7);
  font-size: var(--fs-xs);
  cursor: pointer;
}
</style>
