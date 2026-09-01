<script setup lang="ts">
/* The 238px sticky sidebar from the design.
 *
 * Every row is generated from `nav.ts`. The design's footer block — avatar,
 * name, role, sign-out — is not here. The server does have operators now, so a
 * name and a role would be real; a sign-out button would still sign nobody out
 * of anything, because there is no session to end — the credential is a token
 * in a field, cleared from the token card. The version line and the motto take
 * that space instead, both of which are things the server actually said.
 */

import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from '@/lib/i18n'
import { NAV_PARENT, NAV_SECTIONS, type HintSource, type NavItem } from '@/lib/nav'
import { meta } from '@/services/serverFacts'
import { useNavCounts } from '@/composables/useNavCounts'
import { closeDrawer, drawerOpen } from '@/composables/useNavDrawer'
import StrokeIcon from '@/components/ui/StrokeIcon.vue'

const route = useRoute()
const { t } = useI18n()
const { countFor } = useNavCounts()

const activeId = computed(() => {
  const name = typeof route.name === 'string' ? route.name : ''
  return NAV_PARENT[name] ?? name
})

const versionLine = computed(() =>
  meta.value ? t('sidebarServer', { version: meta.value.version }) : t('sidebarServerUnknown'),
)

/* A hint is a count this app actually holds, or nothing at all. The design's
 * "6" and "#84" were placeholders; a number rendered before the request that
 * would justify it has returned is the whole failure mode this product exists
 * to avoid. */
function hintFor(source: HintSource): string {
  const count = countFor.value(source)
  return count === null ? '' : String(count)
}

function isActive(item: NavItem): boolean {
  return item.id === activeId.value
}
</script>

<template>
  <aside class="sidebar" :class="{ 'sidebar--open': drawerOpen }">
    <div class="brand">
      <span class="mark" aria-hidden="true"><span class="mark-inner" /></span>
      <span class="brand-text">
        <span class="brand-name">waxseal</span>
        <span class="brand-version">{{ versionLine }}</span>
      </span>
      <button type="button" class="drawer-close" :aria-label="t('navClose')" @click="closeDrawer">
        <StrokeIcon name="close" />
      </button>
    </div>

    <template v-for="section in NAV_SECTIONS" :key="section.titleKey">
      <div class="section-title">{{ t(section.titleKey) }}</div>
      <nav class="nav" :aria-label="t(section.titleKey)">
        <RouterLink
          v-for="item in section.items"
          :key="item.id"
          class="nav-row"
          :class="{ 'nav-row--active': isActive(item) }"
          :to="{ name: item.id }"
          :aria-current="isActive(item) ? 'page' : undefined"
        >
          <StrokeIcon :name="item.icon" />
          <span class="nav-label">{{ t(item.labelKey) }}</span>
          <span class="nav-hint">{{ hintFor(item.hint) }}</span>
        </RouterLink>
      </nav>
    </template>

    <p class="motto">{{ t('motto') }}</p>
  </aside>
</template>

<style scoped>
.sidebar {
  width: var(--sidebar-width);
  flex-shrink: 0;
  background: var(--color-canvas);
  border-right: var(--hairline) solid var(--color-hairline);
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}

.brand {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  padding: var(--space-10) var(--space-10) var(--space-7);
}

/* Reachable only while the sidebar is an overlay; above that breakpoint the
 * sidebar is part of the layout and there is nothing to dismiss. */
.drawer-close {
  display: none;
  margin-left: auto;
  border: 0;
  background: transparent;
  cursor: pointer;
  padding: var(--space-2);
  border-radius: var(--radius-nav);
  color: var(--color-ink-muted-48);
}

.mark {
  width: var(--space-14);
  height: var(--space-14);
  border-radius: var(--radius-circle);
  background: var(--color-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.mark-inner {
  width: var(--space-6);
  height: var(--space-6);
  border-radius: var(--radius-circle);
  border: 1.5px solid var(--color-canvas-80);
}

.brand-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.brand-name {
  font-weight: var(--fw-semibold);
  font-size: var(--fs-h4);
  letter-spacing: var(--ls-nav);
}

.brand-version {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
}

.section-title {
  padding: var(--space-3) var(--space-11) var(--space-2);
  font-size: var(--fs-4xs);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-caps);
  text-transform: uppercase;
  color: var(--color-ink-muted-2);
}

.section-title:not(:first-of-type) {
  padding-top: var(--space-7);
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: var(--space-1) var(--space-6);
}

.nav-row {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  padding: var(--space-4) var(--space-6);
  border-radius: var(--radius-nav);
  font-size: var(--fs-md);
  letter-spacing: var(--ls-nav);
  color: var(--color-ink);
  text-decoration: none;
}

.nav-row:hover {
  background: var(--color-canvas-parchment);
  text-decoration: none;
}

.nav-row--active {
  font-weight: var(--fw-semibold);
  color: var(--color-primary);
  background: var(--color-canvas-parchment);
}

.nav-label {
  flex: 1;
}

.nav-hint {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
}

.motto {
  margin-top: auto;
  padding: var(--space-7) var(--space-8);
  border-top: var(--hairline) solid var(--color-divider-soft);
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

/* Below this width a 238px column is two thirds of a phone screen, so the
 * sidebar leaves the flow entirely and slides in over the content instead.
 * `position: fixed` replaces the sticky behaviour rather than joining it —
 * sticky inside a transformed overlay does not resolve against the viewport. */
@media (max-width: 900px) {
  .sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    z-index: var(--z-drawer);
    height: 100%;
    transform: translateX(-100%);
    transition: transform 0.2s ease;
    border-right: var(--hairline) solid var(--color-hairline);
  }

  .sidebar--open {
    transform: translateX(0);
  }

  .drawer-close {
    display: block;
  }
}
</style>
