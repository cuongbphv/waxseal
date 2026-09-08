<script setup lang="ts">
/* API keys: a real store, a real mint, a real revoke.
 *
 * The screen this replaces said there was no key management and that a Revoke
 * button would be a control that does nothing. Both statements were true when
 * they were written and are false now, so they are gone rather than reworded.
 *
 * Three things this screen will not do.
 *
 * It shows a minted key once. There is no reveal affordance anywhere, because
 * the server stored only a SHA-256 and could not honour one — the panel says so
 * BEFORE it is dismissed, not after, and dismissing it is the end of the value.
 * Nothing here writes it to storage, re-fetches it or logs it.
 *
 * It lists revoked keys. A revocation is part of the history an auditor came to
 * read; hiding the row would answer "which credentials existed?" with a smaller
 * set than the truth.
 *
 * It does not call `{revoked: false}` a success. That answer means the key was
 * already revoked or no key has that id, which is a different thing to tell an
 * operator than "the credential is withdrawn".
 */

import { computed, ref, watch } from 'vue'
import { useI18n } from '@/lib/i18n'
import { listOperators } from '@/services/operators'
import { useApiKeys } from '@/composables/useApiKeys'
import { useAsyncData } from '@/composables/useAsyncData'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PrincipalCard from '@/components/app/PrincipalCard.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'
import { needsCredential } from '@/services/serverFacts'
import MintKeyForm from './MintKeyForm.vue'
import MintedKeyPanel from './MintedKeyPanel.vue'
import KeysTable from './KeysTable.vue'

const { t } = useI18n()

const {
  keys,
  minting,
  mintError,
  minted,
  mint,
  dismissMinted,
  revoking,
  revokeError,
  revokeOutcome,
  revoke,
} = useApiKeys()

/* The mint form picks an operator, so it needs the same list the Users screen
 * reads. A failure here is a smaller thing than a failed key list — it costs
 * the picker, not the screen — so it renders as "no operator to mint for"
 * rather than blanking the page. */
const operators = useAsyncData(() => listOperators())

const owner = ref('')
const label = ref('')

/* Default to the first operator once the list arrives, without overwriting a
 * choice already made. */
watch(
  () => operators.data.value,
  (list) => {
    if (!owner.value && list?.length) owner.value = list[0].username
  },
)

const canMint = computed(() => owner.value !== '' && label.value.trim() !== '' && !minting.value)

const columns = computed<Column[]>(() => [
  { key: 'key', label: t('colKey'), track: 'minmax(240px, 1.6fr)' },
  { key: 'fingerprint', label: t('colFingerprint'), track: '170px' },
  { key: 'created', label: t('colCreated'), track: '150px' },
  { key: 'lastUsed', label: t('colLastUsed'), track: '150px' },
  { key: 'status', label: t('colStatus'), track: '190px', align: 'end' },
])

const copied = ref(false)

async function copyMinted(): Promise<void> {
  const secret = minted.value?.key
  if (!secret) return
  try {
    await navigator.clipboard.writeText(secret)
    copied.value = true
    window.setTimeout(() => (copied.value = false), 1200)
  } catch {
    /* Clipboard access can be refused. The value is selectable on screen, and
     * it is deliberately NOT stashed anywhere as a consolation. */
  }
}

function dismiss(): void {
  copied.value = false
  dismissMinted()
}

async function submitMint(): Promise<void> {
  const ok = await mint(owner.value, label.value.trim())
  if (ok) label.value = ''
}

</script>

<template>
  <PageHeader :title="t('keysTitle')" :subtitle="t('keysSub')" />

  <PrincipalCard />

  <AsyncBlock
    :pending="keys.pending.value"
    :started="keys.started.value"
    :error="keys.error.value"
    @retry="keys.run"
  >
    <template #unauthorized><AuthNeeded /></template>

    <MintKeyForm
      :operators="operators.data.value"
      v-model:owner="owner"
      v-model:label="label"
      :can-mint="canMint"
      :minting="minting"
      :mint-error="mintError"
      @mint="submitMint"
    />
    <MintedKeyPanel
      v-if="minted"
      :minted="minted"
      :copied="copied"
      @copy="copyMinted"
      @dismiss="dismiss"
    />
    <KeysTable
      :rows="keys.data.value ?? []"
      :columns="columns"
      :revoking="revoking"
      :revoke-error="revokeError"
      :revoke-outcome="revokeOutcome"
      @revoke="revoke"
    />
  </AsyncBlock>

  <AppCard>
    <h2 class="title">{{ t('patTitle') }}</h2>
    <p class="desc">{{ t('patBody') }}</p>
    <p class="desc">{{ t('adminDocsWhere') }}</p>
  </AppCard>

  <AuthNeeded v-if="needsCredential" />

  <p class="foot">{{ t('tokenSub') }}</p>
</template>

<style scoped>
.title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
  line-height: var(--lh-body);
}

.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
