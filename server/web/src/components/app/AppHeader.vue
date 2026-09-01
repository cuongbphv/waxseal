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
import { toggleDrawer } from '@/composables/useNavDrawer'
import StrokeIcon from '@/components/ui/StrokeIcon.vue'

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
    <button type="button" class="nav-toggle" :aria-label="t('navOpen')" @click="toggleDrawer">
      <StrokeIcon name="menu" />
    </button>

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
  /* NO hand-written `-webkit-` twin here, and adding one back reopens the bug.
   * This rule carried both spellings until 01/09/2026; the build's own
   * autoprefixer then emitted ONLY `-webkit-backdrop-filter`, which Chrome does
   * not implement, so the header lost its frost and became flat 80% white —
   * every row of content scrolling beneath it stayed legible straight through
   * the breadcrumb. Declaring the standard property alone makes the build emit
   * both spellings. Verified against the built bundle, not the source. */
  backdrop-filter: var(--header-blur);
  border-bottom: var(--hairline) solid var(--color-hairline);
  position: sticky;
  top: 0;
  z-index: 5;
  flex-wrap: wrap;
}

/* The frost is what earns the 80% background above: a translucent header with
 * no blur behind it does not hide the content it overlaps. Where the blur
 * cannot render, the header goes opaque rather than quietly staying
 * see-through — the same instinct as rule 6, that a degradation must show
 * itself rather than pass for the working thing. */
@supports not (backdrop-filter: blur(1px)) {
  .header {
    background: var(--color-canvas);
  }
}

/* Shown only where the sidebar has left the flow, so it can never be the
 * second way to reach a nav that is already on screen. */
.nav-toggle {
  display: none;
  border: 0;
  background: transparent;
  cursor: pointer;
  padding: var(--space-2);
  margin-right: var(--space-3);
  border-radius: var(--radius-nav);
  color: var(--color-ink);
}

.crumbs {
  font-size: var(--fs-base);
  color: var(--color-ink-muted-48);
  min-width: 0;
  display: flex;
  gap: var(--space-3);
  align-items: baseline;
  flex: 1;
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

@media (max-width: 900px) {
  .nav-toggle {
    display: block;
  }

  /* The host name is the least useful thing here on a small screen: the
   * operator knows which server they opened. The crumb that says WHERE they
   * are stays. */
  .server,
  .slash {
    display: none;
  }
}

@media (max-width: 560px) {
  /* The head pill is a hash — it cannot usefully shrink, so it drops rather
   * than wrapping the header onto a third line. It is on the trail screen
   * itself, which is the only place it is load-bearing. */
  .head-pill {
    display: none;
  }
}
</style>
