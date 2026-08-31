<script setup lang="ts">
/* Ledger status: the Workstream F surface, none of it configured.
 *
 * The three contracts and their descriptions are real design, so they are
 * shown. Their status is not: nothing was queried, because the `evm` extra is
 * opt-in and this deployment has no RPC endpoint and no contract address. Each
 * card therefore reads "not configured" with the neutral tone — never "live",
 * and never a green dot borrowed from a chain that WAS checked.
 */

import { useI18n } from '@/lib/i18n'
import { LEDGER_CONTRACTS } from '@/content'
import AppCard from '@/components/ui/AppCard.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import FeatureGate from '@/components/app/FeatureGate.vue'

const { t } = useI18n()
</script>

<template>
  <PageHeader :title="t('ledgerTitle')" :subtitle="t('ledgerSub')" />

  <FeatureGate feature="ledger" />

  <div class="grid">
    <AppCard v-for="contract in LEDGER_CONTRACTS" :key="contract.nameKey">
      <div class="head">
        <h2>{{ t(contract.nameKey) }}</h2>
        <StatusPill tone="neutral" :label="t('notConfigured')" :title="t('ledgerUnavailableBody')" />
      </div>
      <p class="desc">{{ t(contract.descriptionKey) }}</p>
      <p class="addr mono">{{ t('ledgerAddrNone') }}</p>
    </AppCard>
  </div>

  <AppCard>
    <h2 class="rpc-title">{{ t('rpcTitle') }}</h2>
    <p class="rpc-none mono">{{ t('rpcNone') }}</p>
    <p class="rpc-foot">{{ t('rpcFoot') }}</p>
  </AppCard>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: var(--space-6);
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  flex-wrap: wrap;
}

h2 {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-nav);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
  line-height: var(--lh-body);
}

.addr {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
  margin-top: var(--space-4);
}

.rpc-title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.rpc-none {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-2);
  margin-top: var(--space-6);
}

.rpc-foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-7);
  line-height: var(--lh-body);
}
</style>
