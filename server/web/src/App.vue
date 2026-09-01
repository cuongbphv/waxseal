<script setup lang="ts">
/* The shell: sidebar, frosted header, content column.
 *
 * The design's content column is `padding: 28px 32px` with an 18–20px gap
 * between blocks; every screen inherits that from here rather than restating
 * it, so no screen can be spaced differently by accident. The padding scalars
 * shrink per breakpoint in `tokens.css`, which is why no view carries a media
 * query of its own.
 *
 * At or below 900px the sidebar becomes an overlay drawer. It closes on a route
 * change and on Escape: a nav that stays open over the screen it just navigated
 * to hides the thing the operator asked for.
 */

import { watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from '@/lib/i18n'
import { closeDrawer, drawerOpen } from '@/composables/useNavDrawer'
import AppSidebar from '@/components/app/AppSidebar.vue'
import AppHeader from '@/components/app/AppHeader.vue'

const { t } = useI18n()
const route = useRoute()

watch(() => route.fullPath, closeDrawer)

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') closeDrawer()
}
</script>

<template>
  <a class="skip-link" href="#main">{{ t('skipToContent') }}</a>
  <div class="shell" @keydown="onKeydown">
    <div
      v-if="drawerOpen"
      class="scrim"
      :aria-label="t('navClose')"
      role="button"
      tabindex="-1"
      @click="closeDrawer"
    />
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

/* Only ever visible while the drawer is, and the drawer only exists below the
 * compact breakpoint. */
.scrim {
  display: none;
}

@media (max-width: 900px) {
  .scrim {
    display: block;
    position: fixed;
    inset: 0;
    z-index: var(--z-scrim);
    border: 0;
    background: var(--drawer-scrim);
  }
}
</style>
