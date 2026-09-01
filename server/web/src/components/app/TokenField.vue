<script setup lang="ts">
/* One bearer token, held for this tab.
 *
 * This is deliberately not a login form even though the server now has
 * operators: there is no password anywhere in the system, because the key IS
 * the credential. A form asking for an email and a password would be
 * authenticating against something that does not exist. What the field does is
 * exactly what it says — it holds the value that goes in an
 * `Authorization: Bearer` header on /v1 reads, and `/v1/whoami` is what says
 * whose value it is.
 *
 * sessionStorage, not localStorage: a credential that outlives the tab is a
 * credential nobody remembers leaving behind.
 */

import { computed, ref } from 'vue'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { clearToken, setToken, token } from '@/lib/session'
import { meta } from '@/services/serverFacts'
import AppCard from '@/components/ui/AppCard.vue'
import PillButton from '@/components/ui/PillButton.vue'

const { t } = useI18n()
const draft = ref(token.value)

/* Three answers, and the middle one matters: a server with no key accepts /v1
 * reads outright. Telling an operator a credential is "required" on a
 * deployment where it is not would send them hunting for one that does not
 * exist — and would misdescribe the deployment's actual exposure.
 *
 * `write_auth` flips to `bearer_required` as soon as ANY key exists, so
 * minting the first one closes the server. This line therefore has to be
 * re-read after a mint rather than left standing; `useApiKeys` re-runs
 * `loadServerFacts` for exactly that. */
const requirementKey = computed<MessageKey>(() => {
  const auth = meta.value?.write_auth
  if (auth === 'bearer_required') return 'authNeeded'
  if (auth === 'open') return 'authOpen'
  return 'authUnknown'
})

function apply(): void {
  setToken(draft.value)
}

function forget(): void {
  draft.value = ''
  clearToken()
}
</script>

<template>
  <AppCard>
    <h2 class="title">{{ t('tokenTitle') }}</h2>
    <p class="sub">{{ t(requirementKey) }}</p>
    <form class="row" @submit.prevent="apply">
      <label class="label" for="waxseal-token">{{ t('authField') }}</label>
      <input
        id="waxseal-token"
        v-model="draft"
        class="input mono"
        type="password"
        autocomplete="off"
        spellcheck="false"
      />
      <PillButton type="submit">{{ t('authApply') }}</PillButton>
      <PillButton v-if="token" variant="outline" @click="forget">{{ t('authClear') }}</PillButton>
    </form>
    <p class="hint">{{ t('authHint') }}</p>
  </AppCard>
</template>

<style scoped>
.title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.sub {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-1);
}

.row {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  margin-top: var(--space-6);
  flex-wrap: wrap;
}

.label {
  font-size: var(--fs-3xs);
  font-family: var(--font-mono);
  color: var(--color-ink-muted-2);
}

.input {
  flex: 1;
  min-width: 220px;
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--color-hairline);
  background: var(--color-surface-pearl);
  outline: none;
}

.input:focus {
  border-color: var(--color-primary-focus);
}

.hint {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-6);
  line-height: var(--lh-body);
}
</style>
