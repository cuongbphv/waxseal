<script setup lang="ts">
/* Preflight: the six-tier attacker ladder, unmeasured.
 *
 * The tiers are real — the threat model defines them and the defences named
 * beside them are the ones the library implements. What this build cannot do
 * is say which tier a given deployment is AT: there is no `preflight`
 * subcommand, so nothing was measured. Every badge therefore reads "not
 * measured" in the neutral style, and tier 4 is NOT marked current: the design
 * highlights it, but a highlight is a finding and no finding was made.
 *
 * When Workstream E ships the command, `FeatureGate` mounts the real output
 * above the ladder and no code here changes.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'
import { TIERS } from '@/content'
import { loadPreflight } from '@/services/chains'
import { useChainDirectory } from '@/composables/useChainDirectory'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import FeatureGate from '@/components/app/FeatureGate.vue'
import ScopeStatement from '@/components/app/ScopeStatement.vue'
import CommandOutput from '@/components/trail/CommandOutput.vue'

const { t } = useI18n()
const directory = useChainDirectory()

/* The command is per-chain. With no chain there is nothing to preflight, and
 * that stays true however capable the build becomes. */
const firstChain = computed(() => directory.ids.value?.[0] ?? null)
</script>

<template>
  <PageHeader :title="t('preflightTitle')" :subtitle="t('preflightSub')" />

  <FeatureGate feature="preflight">
    <template #available>
      <CommandOutput v-if="firstChain" :run="() => loadPreflight(firstChain!)" />
    </template>
  </FeatureGate>

  <ul class="ladder">
    <li v-for="tier in TIERS" :key="tier.numberKey">
      <AppCard size="panel">
        <div class="tier">
          <span class="n">{{ t(tier.numberKey) }}</span>
          <span class="text">
            <span class="attack">{{ t(tier.attackKey) }}</span>
            <span class="defense">{{ t(tier.defenseKey) }}</span>
          </span>
          <Badge :title="t('notMeasuredWhy')">{{ t('preflightBadgeUnmeasured') }}</Badge>
        </div>
      </AppCard>
    </li>
  </ul>

  <AppCard size="panel">
    <p class="claim mono">{{ t('preflightScopeLine') }}</p>
    <p class="claim mono">
      {{ t('preflightTailLine') }}
      <span class="scoped">{{ t('preflightTailClaim') }}</span>
    </p>
    <ScopeStatement form="statement" />
  </AppCard>
</template>

<style scoped>
.ladder {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.tier {
  display: flex;
  align-items: center;
  gap: var(--space-8);
}

.n {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
  width: 56px;
  flex-shrink: 0;
  color: var(--color-ink-muted-2);
}

.text {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.attack {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-nav);
}

.defense {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-1);
}

.claim {
  font-size: var(--fs-xs);
  line-height: var(--lh-mono);
}

/* "tamper-evident" is the headline claim; the scoped word beside it is what
 * keeps it from reading as "tamper-proof", which this app never prints. */
.scoped {
  color: var(--color-text-caution);
  font-weight: var(--fw-semibold);
}
</style>
