<script setup lang="ts">
/* "This read needs a credential" — one line, pointing at Settings.
 *
 * It replaces the full token card that used to be mounted on nine screens. A
 * credential field repeated twelve times is twelve places to paste a key into
 * and twelve places to leave one behind, and it made the token look like a
 * property of whichever screen you happened to be on rather than of the
 * session. The field lives in Settings now; this says so and gets out of the
 * way.
 */

import { useI18n } from '@/lib/i18n'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()
</script>

<template>
  <TintPanel :title="t('authNeededTitle')">
    {{ t('authNeededBody') }}
    <template #aside>
      <RouterLink class="go" :to="{ name: 'settings' }">{{ t('authNeededLink') }}</RouterLink>
    </template>
  </TintPanel>
</template>

<style scoped>
.go {
  align-self: flex-start;
  margin-top: var(--space-4);
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}
</style>
