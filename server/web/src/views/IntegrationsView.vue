<script setup lang="ts">
/* The nine integrations the library ships.
 *
 * The providers, their mechanisms and their install commands are facts about
 * the library. Whether one is INSTALLED is not a fact this server can have:
 * a hook lives in the agent framework's home directory on whichever machine
 * runs the agent, and this server never looks there. So every dot is neutral
 * and means "not detected from here" — which is a different claim from "not
 * installed", and the panel above says which one is being made.
 */

import { useI18n } from '@/lib/i18n'
import { PROVIDERS } from '@/content'
import AppCard from '@/components/ui/AppCard.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusDot from '@/components/ui/StatusDot.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()
</script>

<template>
  <PageHeader :title="t('intTitle')" :subtitle="t('intSub')" />

  <TintPanel :title="t('intDetectTitle')">{{ t('intDetectBody') }}</TintPanel>

  <div class="grid">
    <AppCard v-for="provider in PROVIDERS" :key="provider.name">
      <div class="head">
        <span class="mark mono" aria-hidden="true">{{ provider.mono }}</span>
        <h2>{{ provider.name }}</h2>
      </div>
      <p class="mech">{{ t(provider.mechanismKey) }}</p>
      <div class="foot">
        <code class="install mono">{{ provider.install }}</code>
        <StatusDot tone="neutral" :label="t('notDetected')" :title="t('intDetectBody')" size="sm" />
      </div>
    </AppCard>
  </div>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--space-6);
}

.head {
  display: flex;
  align-items: center;
  gap: var(--space-5);
}

.mark {
  width: var(--avatar-size);
  height: var(--avatar-size);
  border-radius: var(--radius-tile);
  background: var(--color-canvas-parchment);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
  color: var(--color-primary);
  flex-shrink: 0;
}

h2 {
  font-size: var(--fs-md);
  font-weight: var(--fw-semibold);
}

.mech {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
  line-height: var(--lh-body);
}

.foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  margin-top: var(--space-6);
  flex-wrap: wrap;
}

.install {
  font-size: var(--fs-4xs);
  color: var(--color-ink-muted-48);
}
</style>
