<script setup lang="ts">
/* The sidecar grid, driven entirely by `report` plus the two receipt checks.
 *
 * The two receipt cards are separate on purpose. `verify` asks whether the
 * acknowledgment log is internally consistent — it stays `ok` after an edit to
 * the trail, because the log itself was not touched. `cross-check` asks
 * whether entry `seq` still carries the hash acknowledged for it, which is the
 * one that catches a self-consistent local rewrite. Merging them into a single
 * ".receipts: ok" would answer the easier question and label it the harder one.
 *
 * `.sealkey` has no server endpoint, so it says that rather than borrowing a
 * neighbouring card's verdict.
 */

import { computed } from 'vue'
import type { ReportOutcome } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { checkSummary, droppedWrites, receiptsChecked, type Measurement } from '@/lib/measure'
import { toneOfVerdict } from '@/lib/states'
import { loadReport } from '@/services/chains'
import { loadReceiptChecks, type ChainReceiptChecks } from '@/services/receipts'
import { useAsyncData } from '@/composables/useAsyncData'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import TokenField from '@/components/app/TokenField.vue'
import SidecarCard from './SidecarCard.vue'

const props = defineProps<{ chainId: string }>()

const { t } = useI18n()

const report = useAsyncData<ReportOutcome>(() => loadReport(props.chainId), {
  watching: [() => props.chainId],
})

const checks = useAsyncData<ChainReceiptChecks>(() => loadReceiptChecks(props.chainId), {
  watching: [() => props.chainId],
})

const body = computed(() => report.data.value?.report ?? null)

const notRecorded = computed<Measurement>(() => ({
  text: t('notRecorded'),
  title: t('notMeasuredWhy'),
  tone: 'neutral',
}))

const attest = computed(() => (body.value ? checkSummary(body.value.attestations) : notRecorded.value))
const anchors = computed(() => (body.value ? checkSummary(body.value.anchors) : notRecorded.value))
const pin = computed(() => (body.value ? checkSummary(body.value.pin) : notRecorded.value))

const drops = computed<Measurement>(() =>
  body.value
    ? droppedWrites(body.value.completeness.dropped_writes, body.value.completeness.drops_source)
    : notRecorded.value,
)

const receiptsVerify = computed<Measurement>(() => {
  const check = checks.data.value?.verify
  if (!check?.resolved) return notRecorded.value
  const { verdict, checked, reason, broken_receipt_seq: brokenSeq, exit_code: exit } = check.value
  return {
    text: receiptsChecked(checked, reason),
    title: [
      `${verdict} · ${t('exitLabel', { code: exit })}`,
      reason,
      brokenSeq === null ? null : t('receiptsBrokenReceiptSeq', { seq: brokenSeq }),
    ]
      .filter(Boolean)
      .join(' · '),
    tone: checked === null ? 'neutral' : toneOfVerdict(verdict),
  }
})

const receiptsCross = computed<Measurement>(() => {
  const check = checks.data.value?.crossCheck
  if (!check?.resolved) return notRecorded.value
  const { verdict, checked, reason, broken_seq: brokenSeq, exit_code: exit } = check.value
  return {
    text: receiptsChecked(checked, reason),
    title: [
      `${verdict} · ${t('exitLabel', { code: exit })}`,
      reason,
      brokenSeq === null ? null : t('receiptsBrokenSeq', { seq: brokenSeq }),
    ]
      .filter(Boolean)
      .join(' · '),
    tone: checked === null ? 'neutral' : toneOfVerdict(verdict),
  }
})

const sealkey = computed<Measurement>(() => ({
  text: t('unavailableHere'),
  title: t('sidecarSealkeyStatus'),
  tone: 'neutral',
}))
</script>

<template>
  <AsyncBlock
    :pending="report.pending.value"
    :started="report.started.value"
    :error="report.error.value"
    @retry="report.run"
  >
    <template #unauthorized><TokenField /></template>

    <div class="grid">
      <SidecarCard :name="t('sidecarAttest')" :description="t('sidecarAttestDesc')" :status="attest" />
      <SidecarCard :name="t('sidecarAnchors')" :description="t('sidecarAnchorsDesc')" :status="anchors" />
      <SidecarCard :name="t('sidecarDrops')" :description="t('sidecarDropsDesc')" :status="drops" />
      <SidecarCard :name="t('sidecarPin')" :description="t('sidecarPinDesc')" :status="pin" />
      <SidecarCard
        :name="t('sidecarReceiptsVerify')"
        :description="t('sidecarReceiptsVerifyDesc')"
        :status="receiptsVerify"
      />
      <SidecarCard
        :name="t('sidecarReceiptsCross')"
        :description="t('sidecarReceiptsCrossDesc')"
        :status="receiptsCross"
      />
      <SidecarCard
        :name="t('sidecarSealkey')"
        :description="t('sidecarSealkeyDesc')"
        :status="sealkey"
      />
    </div>
  </AsyncBlock>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: var(--space-6);
}
</style>
