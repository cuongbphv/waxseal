<script setup lang="ts">
/* The sticky frosted header: breadcrumb left, controls right.
 *
 * The design's `head <hash>` pill shows a running head. There is only a head
 * to show when a chain is in context, so on every other screen the pill says
 * which of the two reasons it is empty for — no chain selected, or a chain
 * with no entries — rather than printing a plausible-looking hash.
 *
 * The `read-only` pill is a claim, so it carries the sentence that scopes it:
 * this console appends nothing to a chain, ever.
 */

import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { LANGS, useI18n, type Lang, type MessageKey } from '@/lib/i18n'
import { shortHash } from '@/lib/format'
import { activeHead } from '@/composables/useActiveChain'

const route = useRoute()
const { t, lang, setLang } = useI18n()

/* The server this console is served from. Read off the location rather than
 * configured: a name typed into a build would go stale behind a proxy. */
const serverName = computed(() => window.location.host)

const crumb = computed(() => {
  const key = route.meta.crumbKey as MessageKey | undefined
  if (route.name === 'trail') return String(route.params.id ?? '')
  return key ? t(key) : ''
})

const headPill = computed(() => {
  const head = activeHead.value
  if (head === 'no-chain') return { text: t('headPillNoChain'), title: t('headPillNoChain') }
  if (head === 'empty') return { text: t('headPillEmpty'), title: t('chainEmpty') }
  return {
    text: t('headPill', { hash: shortHash(head.entry_hash) }),
    title: `seq ${head.seq} · ${head.entry_hash}`,
  }
})

const langLabels: Record<Lang, MessageKey> = { vi: 'langVi', en: 'langEn' }
</script>

<template>
  <header class="header">
    <nav class="crumbs" :aria-label="t('sectionPortal')">
      <span class="server">{{ serverName }}</span>
      <span class="slash" aria-hidden="true">/</span>
      <span class="here">{{ crumb }}</span>
    </nav>

    <div class="controls">
      <div class="lang" role="group" :aria-label="t('langEn')">
        <button
          v-for="option in LANGS"
          :key="option"
          type="button"
          class="lang-option"
          :class="{ 'lang-option--on': lang === option }"
          :aria-pressed="lang === option"
          @click="setLang(option)"
        >
          {{ t(langLabels[option]) }}
        </button>
      </div>

      <span class="head-pill mono" :title="headPill.title">{{ headPill.text }}</span>

      <span class="ro-pill" :title="t('readOnlyTitle')">{{ t('readOnly') }}</span>
    </div>
  </header>
</template>

<style scoped>
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-8);
  padding: var(--header-pad-y) var(--content-pad-x);
  background: var(--color-canvas-80);
  backdrop-filter: var(--header-blur);
  -webkit-backdrop-filter: var(--header-blur);
  border-bottom: var(--hairline) solid var(--color-hairline);
  position: sticky;
  top: 0;
  z-index: 5;
  flex-wrap: wrap;
}

.crumbs {
  font-size: var(--fs-base);
  color: var(--color-ink-muted-48);
  min-width: 0;
  display: flex;
  gap: var(--space-3);
  align-items: baseline;
}

.slash {
  color: var(--color-surface-chip-translucent);
}

.here {
  color: var(--color-ink);
  font-weight: var(--fw-semibold);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.controls {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  flex-wrap: wrap;
}

.lang {
  display: flex;
  border: var(--hairline) solid var(--color-hairline);
  border-radius: var(--radius-pill);
  overflow: hidden;
  background: var(--color-canvas);
}

.lang-option {
  border: 0;
  cursor: pointer;
  font-size: var(--fs-3xs);
  font-weight: var(--fw-semibold);
  padding: var(--space-2) var(--space-6);
  color: var(--color-ink-muted-48);
  background: transparent;
}

.lang-option--on {
  color: var(--color-on-primary);
  background: var(--color-primary);
}

.head-pill {
  font-size: var(--fs-3xs);
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-pill);
  background: var(--color-canvas-parchment);
  color: var(--color-ink-muted-48);
  max-width: 22em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ro-pill {
  font-size: var(--fs-3xs);
  font-weight: var(--fw-semibold);
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-pill);
  background: var(--tint-blue);
  color: var(--color-primary);
}
</style>
