<script setup lang="ts">
/* One trail: header, verdict banner, four tabs.
 *
 * The banner prints the verdict AND the frozen scope line beside it, because a
 * verdict without its scope is a stronger claim than the verifier made. The
 * three buttons run real commands and the Output tab shows their argv above
 * their stdout — a conclusion shown without the command that produced it is
 * asking to be trusted.
 *
 * There is no control on this screen that edits, deletes, reorders or repairs
 * anything, and there is no place to add one: every route the server exposes
 * to this console is read-only by construction (`READ_ONLY_COMMANDS`).
 */

import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import type { ChainSummary, Outcome } from '@/lib/api'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { countLabel } from '@/lib/format'
import { stateOf } from '@/lib/states'
import { api } from '@/lib/api'
import { TRAIL_ACTIONS, runTrailAction, type TrailAction } from '@/services/chains'
import { useAsyncData } from '@/composables/useAsyncData'
import { clearActiveHead, setActiveHead } from '@/composables/useActiveChain'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import OutputPanel from '@/components/ui/OutputPanel.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import ScopeStatement from '@/components/app/ScopeStatement.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'
import TrailEntriesTab from '@/components/trail/TrailEntriesTab.vue'
import TrailSegmentsTab from '@/components/trail/TrailSegmentsTab.vue'
import TrailSidecarsTab from '@/components/trail/TrailSidecarsTab.vue'

const props = defineProps<{ id: string; tab?: string }>()

const { t } = useI18n()
const router = useRouter()

/* The tab lives in the URL so a sidecar tab of a specific trail is linkable. */
const TABS = [
  { id: 'entries', labelKey: 'tabEntries' },
  { id: 'segments', labelKey: 'tabSegments' },
  { id: 'sidecars', labelKey: 'tabSidecars' },
  { id: 'output', labelKey: 'tabOutput' },
] as const satisfies readonly { id: string; labelKey: MessageKey }[]

type TabId = (typeof TABS)[number]['id']

const activeTab = computed<TabId>(() => {
  const wanted = props.tab
  return TABS.some((tab) => tab.id === wanted) ? (wanted as TabId) : 'entries'
})

function goToTab(tab: TabId): void {
  void router.replace({ name: 'trail', params: { id: props.id, tab } })
}

/* ------------------------------------------------------------- chain facts */

const summary = useAsyncData<ChainSummary>(() => api.summary(props.id), {
  watching: [() => props.id],
})

/* The header pill needs the head, and only this screen knows it. Three states:
 * a head, an empty chain, or no chain in context at all. */
watch(
  () => summary.data.value,
  (value) => setActiveHead(value ? (value.head ?? 'empty') : 'no-chain'),
  { immediate: true },
)
onBeforeUnmount(clearActiveHead)

const headSeq = computed(() => summary.data.value?.head?.seq ?? null)

const subtitle = computed(() => {
  const value = summary.data.value
  if (!value) return undefined
  if (value.head === null) return t('chainEmpty')
  return `${countLabel(value.entries)} · ${t('chainHead', { seq: value.head.seq })}`
})

/* --------------------------------------------------------------- verdict */

const verify = useAsyncData<Outcome>(() => api.verify(props.id), {
  watching: [() => props.id],
})

const verdictState = computed(() =>
  verify.data.value ? stateOf(verify.data.value.status) : null,
)

/* ------------------------------------------------------------ the buttons */

const action = ref<TrailAction>('verify')
const actionOutcome = useAsyncData<Outcome>(() => runTrailAction(props.id, action.value, headSeq.value), {
  immediate: false,
})

function run(next: TrailAction): void {
  action.value = next
  goToTab('output')
}

function disabledReason(needsHead: boolean): string | undefined {
  return needsHead && headSeq.value === null ? t('runProofEmptyTitle') : undefined
}

/* One place decides when a command runs: being on the Output tab, for a given
 * chain and action. A deep link straight to the tab therefore produces output
 * — an empty panel would read as "the command returned nothing" rather than
 * "the command was never run" — and a button press cannot double-fire it. */
watch(
  [activeTab, action, () => props.id],
  ([tab]) => {
    if (tab === 'output') void actionOutcome.run()
  },
  { immediate: true },
)
</script>

<template>
  <PageHeader :title="id" :subtitle="subtitle" mono>
    <template #above>
      <RouterLink class="back" :to="{ name: 'dashboard' }">{{ t('backToDashboard') }}</RouterLink>
    </template>
    <template #actions>
      <PillButton
        v-for="descriptor in TRAIL_ACTIONS"
        :key="descriptor.id"
        :variant="descriptor.id === 'verify' ? 'primary' : 'outline'"
        :disabled="descriptor.needsHead && headSeq === null"
        :title="disabledReason(descriptor.needsHead)"
        @click="run(descriptor.id)"
      >
        {{ t(descriptor.labelKey) }}
      </PillButton>
    </template>
  </PageHeader>

  <AsyncBlock
    :pending="verify.pending.value"
    :started="verify.started.value"
    :error="verify.error.value"
    @retry="verify.run"
  >
    <template #unauthorized><AuthNeeded /></template>

    <TintPanel v-if="verify.data.value && verdictState" :tone="verdictState.tone" role="status">
      <template #aside>
        <div class="banner">
          <span class="verdict mono" :class="`verdict--${verdictState.tone}`">
            {{ verdictState.label }} ·
            {{ verify.data.value.exit_code === null
              ? t('exitNone')
              : t('exitLabel', { code: verify.data.value.exit_code }) }}
          </span>
          <span class="explain">{{ t(verdictState.explanationKey) }}</span>
        </div>
        <ScopeStatement />
      </template>
    </TintPanel>
  </AsyncBlock>

  <nav class="tabs" :aria-label="t('navTrail')">
    <PillButton
      v-for="tab in TABS"
      :key="tab.id"
      variant="tab"
      :active="activeTab === tab.id"
      @click="goToTab(tab.id)"
    >
      {{ t(tab.labelKey) }}
    </PillButton>
  </nav>

  <TrailEntriesTab v-if="activeTab === 'entries'" :chain-id="id" />
  <TrailSegmentsTab v-else-if="activeTab === 'segments'" :chain-id="id" />
  <TrailSidecarsTab v-else-if="activeTab === 'sidecars'" :chain-id="id" />
  <template v-else>
    <AsyncBlock
      :pending="actionOutcome.pending.value"
      :started="actionOutcome.started.value"
      :error="actionOutcome.error.value"
      @retry="actionOutcome.run"
    >
      <template #unauthorized><AuthNeeded /></template>
      <OutputPanel
        v-if="actionOutcome.data.value"
        :argv="actionOutcome.data.value.argv"
        :stdout="actionOutcome.data.value.stdout"
        :stderr="actionOutcome.data.value.stderr"
        :exit-code="actionOutcome.data.value.exit_code"
      />
    </AsyncBlock>
    <p class="foot">{{ t('verifyFoot') }}</p>
  </template>
</template>

<style scoped>
.back {
  font-size: var(--fs-base);
  display: inline-block;
  margin-bottom: var(--space-4);
}

.banner {
  display: flex;
  align-items: baseline;
  gap: var(--space-7);
  flex-wrap: wrap;
}

.verdict {
  font-size: var(--fs-base);
  font-weight: var(--fw-semibold);
}

.verdict--ok {
  color: var(--status-text-ok);
}

.verdict--broken {
  color: var(--status-text-broken);
}

.verdict--unverifiable {
  color: var(--status-text-unverifiable);
}

.verdict--neutral {
  color: var(--status-text-neutral);
}

.explain {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
}

.tabs {
  display: flex;
  gap: var(--space-3);
  flex-wrap: wrap;
}

.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
}
</style>
