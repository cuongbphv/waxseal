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
import { KEY_ID_SHORT_CHARS } from '@/lib/constants'
import { shortHash, tsLabel } from '@/lib/format'
import type { ApiKeyRecord } from '@/lib/api'
import { listOperators, mintKeyErrorKey } from '@/services/operators'
import { useApiKeys } from '@/composables/useApiKeys'
import { useAsyncData } from '@/composables/useAsyncData'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import DataTable from '@/components/ui/DataTable.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import PrincipalCard from '@/components/app/PrincipalCard.vue'
import TokenField from '@/components/app/TokenField.vue'

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

function ownerLabel(row: ApiKeyRecord): string {
  return t('keyOwner', { username: row.username })
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
    <template #unauthorized><TokenField /></template>

    <AppCard>
      <h2 class="title">{{ t('mintTitle') }}</h2>

      <p v-if="operators.data.value && !operators.data.value.length" class="desc">
        {{ t('mintNoOperators') }}
      </p>

      <form class="form" @submit.prevent="submitMint">
        <label class="field">
          <span class="label">{{ t('mintOperator') }}</span>
          <select v-model="owner" class="input mono">
            <option v-for="operator in operators.data.value ?? []" :key="operator.username" :value="operator.username">
              {{ operator.username }} · {{ operator.role }}
            </option>
          </select>
        </label>

        <label class="field">
          <span class="label">{{ t('mintLabel') }}</span>
          <input v-model="label" class="input" type="text" autocomplete="off" spellcheck="false" />
          <span class="hint">{{ t('mintLabelHint') }}</span>
        </label>

        <div class="submit">
          <PillButton type="submit" :disabled="!canMint">
            {{ minting ? t('mintMinting') : t('mintSubmit') }}
          </PillButton>
        </div>
      </form>
    </AppCard>

    <!-- The plaintext, in the design's tint panel, held in one ref and nowhere
         else. The warning is above the value, not below it: "you cannot get
         this back" is only useful before the dismiss button is pressed. -->
    <TintPanel v-if="minted" :title="t('mintedTitle')" role="status">
      {{ t('mintedBody') }}

      <template #aside>
        <div class="secret">
          <code class="secret-value">{{ minted.key }}</code>
          <PillButton variant="outline" @click="copyMinted">
            {{ copied ? t('mintedCopied') : t('mintedCopy') }}
          </PillButton>
          <PillButton @click="dismiss">{{ t('mintedDismiss') }}</PillButton>
        </div>
        <p class="secret-for mono">
          {{ t('mintedFor', { label: minted.label, username: minted.username }) }}
        </p>
      </template>
    </TintPanel>

    <TintPanel v-if="mintError" tone="broken" role="status">
      {{
        t(mintKeyErrorKey(mintError), {
          username: owner,
          detail: mintError.detail || mintError.code,
        })
      }}
    </TintPanel>

    <TintPanel v-if="revokeError" tone="broken" role="status">
      {{ t('revokeFailed', { detail: revokeError.detail || revokeError.code }) }}
    </TintPanel>

    <!-- `revoked: false` is an outcome, not a failure and not a success. It
         gets the neutral ground and says exactly what the server answered. -->
    <TintPanel
      v-else-if="revokeOutcome"
      :tone="revokeOutcome.revoked ? 'ok' : 'neutral'"
      role="status"
    >
      {{
        revokeOutcome.revoked
          ? t('revokeDone', { label: revokeOutcome.key.label })
          : t('revokeNothing', { label: revokeOutcome.key.label })
      }}
    </TintPanel>

    <AppCard flush scroll-x>
      <DataTable
        :columns="columns"
        :rows="keys.data.value ?? []"
        :row-key="(row) => row.key_id"
        min-width="var(--table-min-keys)"
      >
        <template #cell-key="{ row }">
          <div class="name truncate">{{ row.label }}</div>
          <div class="owner mono truncate">
            {{ ownerLabel(row) }} · {{ shortHash(row.key_id, KEY_ID_SHORT_CHARS) }}
          </div>
        </template>

        <template #cell-fingerprint="{ row }">
          <span class="mono stamp">{{ row.fingerprint }}</span>
        </template>

        <template #cell-created="{ row }">
          <span class="mono stamp">{{ tsLabel(row.created_at) }}</span>
        </template>

        <!-- `null` is "never used", which is a fact about the key. It is never
             rendered as a date and never as a blank cell. -->
        <template #cell-lastUsed="{ row }">
          <span v-if="row.last_used_at" class="mono stamp">{{ tsLabel(row.last_used_at) }}</span>
          <span v-else class="stamp muted-2" :title="t('keyNeverUsedWhy')">
            {{ t('keyNeverUsed') }}
          </span>
        </template>

        <template #cell-status="{ row }">
          <div class="status">
            <StatusPill v-if="row.active" tone="ok" :label="t('keyActive')" />
            <StatusPill
              v-else
              tone="neutral"
              :label="t('keyRevoked')"
              :title="row.revoked_at ? t('keyRevokedAt', { at: tsLabel(row.revoked_at) }) : undefined"
            />
            <PillButton
              v-if="row.active"
              variant="outline"
              :disabled="revoking === row.key_id"
              @click="revoke(row)"
            >
              {{ revoking === row.key_id ? t('revoking') : t('revoke') }}
            </PillButton>
          </div>
        </template>

        <template #empty>{{ t('keysNone') }}</template>
        <template #foot>{{ t('keysFoot') }}</template>
      </DataTable>
    </AppCard>
  </AsyncBlock>

  <AppCard>
    <h2 class="title">{{ t('patTitle') }}</h2>
    <p class="desc">{{ t('patBody') }}</p>
    <p class="desc">{{ t('adminDocsWhere') }}</p>
  </AppCard>

  <TokenField />

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

.form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: var(--space-6);
  align-items: start;
  margin-top: var(--space-8);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  min-width: 0;
}

.label {
  font-size: var(--fs-3xs);
  font-family: var(--font-mono);
  color: var(--color-ink-muted-2);
}

.input {
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--color-hairline);
  background: var(--color-surface-pearl);
  outline: none;
  min-width: 0;
}

.input:focus {
  border-color: var(--color-primary-focus);
}

.hint {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

.submit {
  display: flex;
  align-items: flex-end;
  align-self: end;
}

.secret {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  flex-wrap: wrap;
  margin-top: var(--space-6);
}

.secret-value {
  flex: 1;
  min-width: 260px;
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--tint-blue-border);
  background: var(--color-canvas);
  overflow-wrap: anywhere;
  user-select: all;
}

.secret-for {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
}

.name {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.owner {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
  margin-top: var(--space-1);
}

.stamp {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
}

.status {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-4);
  flex-wrap: wrap;
}

/* `button.pill`, not `.pill`: PillButton and StatusPill share the class name,
 * and shrinking the status lozenge along with the control would make the word
 * inside it smaller than every other verdict word in the console. */
.status :deep(button.pill) {
  padding: var(--space-2) var(--space-7);
  font-size: var(--fs-xs);
}

.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
