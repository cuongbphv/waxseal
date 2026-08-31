<script setup lang="ts">
/* The shell: sidebar, frosted header, content column.
 *
 * The design's content column is `padding: 28px 32px` with an 18–20px gap
 * between blocks; every screen inherits that from here rather than restating
 * it, so no screen can be spaced differently by accident.
 */

import { useI18n } from '@/lib/i18n'
import AppSidebar from '@/components/app/AppSidebar.vue'
import AppHeader from '@/components/app/AppHeader.vue'

const { t } = useI18n()
</script>

<template>
  <a class="skip-link" href="#main">{{ t('skipToContent') }}</a>
  <div class="shell">
    <AppSidebar />
    <main class="main">
      <AppHeader />
      <div id="main" class="content">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  min-height: 100vh;
  background: var(--color-canvas-parchment);
}

.main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.content {
  padding: var(--content-pad-y) var(--content-pad-x);
  display: flex;
  flex-direction: column;
  gap: var(--content-gap-lg);
}
</style>
