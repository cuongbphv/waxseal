<script setup lang="ts">
/* `consistency` — does a checkpoint an operator already holds still sit on this
 * chain's history?
 *
 * The seq and root are typed in, not read back from the chain. A screen that
 * filled them from the same trail it then checked would be asking the chain to
 * vouch for itself; the value of this read is that the operator holds the older
 * root independently.
 *
 * A root this chain never had is a positively detected disagreement, not an
 * unknown — the comparison is deterministic — so the verdict is `broken`.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'
import { runConsistency } from '@/services/chains'
import { useChainDirectory } from '@/composables/useChainDirectory'
import PageHeader from '@/components/ui/PageHeader.vue'
import CommandForm, { type Field } from '@/components/app/CommandForm.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const chains = computed(() => directory.ids.value ?? [])

const fields = computed<readonly Field[]>(() => [
  { name: 'chain', label: t('consChain'), options: chains.value },
  { name: 'old_seq', label: t('consOldSeq'), placeholder: '0' },
  { name: 'old_root', label: t('consOldRoot'), placeholder: t('consRootShape') },
])

const blockedReason = computed(() => (chains.value.length === 0 ? t('consNoChains') : undefined))

function run(values: Record<string, string>) {
  return runConsistency(values.chain, values.old_seq, values.old_root)
}
</script>

<template>
  <PageHeader :title="t('consTitle')" :subtitle="t('consSub')" />
  <CommandForm :key="chains.length" :fields="fields" :run="run" :blocked-reason="blockedReason" />
</template>
