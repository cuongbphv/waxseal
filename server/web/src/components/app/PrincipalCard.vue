<script setup lang="ts">
/* Who the token in hand actually is, from `/v1/whoami`.
 *
 * This exists for one honesty rule: a synthetic principal is not a user. The
 * server reports `is_operator: false` for the bootstrap WAXSEAL_API_KEY and for
 * a deployment with no credential configured at all, and both would otherwise
 * be tempting to draw as a person — they have a username and a role. They have
 * no record in the store, so neither appears in the operator table, and this
 * card says which of the two is in play rather than printing one vague notice
 * for both.
 *
 * Scopes come from the server's own answer. Deriving them here from the role
 * would be a second permission model to reconcile against the enforced one.
 */

import { computed } from 'vue'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { KEY_ID_SHORT_CHARS, SYNTHETIC_BOOTSTRAP, SYNTHETIC_OPEN } from '@/lib/constants'
import { shortHash } from '@/lib/format'
import { principal, principalError } from '@/services/serverFacts'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()

/* Which notice a synthetic principal gets. The two usernames are the server's
 * own markers for its two credential-without-an-owner cases; anything else
 * carrying `is_operator: false` gets the general form rather than being
 * described as one of the two it might not be. */
const SYNTHETIC_COPY: Readonly<Record<string, { title: MessageKey; body: MessageKey }>> = {
  [SYNTHETIC_BOOTSTRAP]: { title: 'principalBootstrapTitle', body: 'principalBootstrapBody' },
  [SYNTHETIC_OPEN]: { title: 'principalOpenTitle', body: 'principalOpenBody' },
}

const synthetic = computed(() => {
  const who = principal.value
  if (!who || who.is_operator) return null
  return (
    SYNTHETIC_COPY[who.username] ?? {
      title: 'principalSyntheticTitle' as MessageKey,
      body: 'principalSyntheticBody' as MessageKey,
    }
  )
})

const operator = computed(() => {
  const who = principal.value
  return who && who.is_operator ? who : null
})
</script>

<template>
  <!-- A 401 is not this card's story to tell: the screen's own AsyncBlock
       already asks for a credential, and a second notice saying the same thing
       reads as two separate failures. -->
  <TintPanel v-if="synthetic" :title="t(synthetic.title)" role="status">
    {{ t(synthetic.body) }}
  </TintPanel>

  <AppCard v-else-if="operator">
    <div class="line">
      <h2 class="title">{{ t('principalOperator', { username: operator.username }) }}</h2>
      <Badge mono :title="t('colRole')">{{ operator.role }}</Badge>
      <span v-if="operator.key_id" class="mono key">
        {{ t('principalKey', { id: shortHash(operator.key_id, KEY_ID_SHORT_CHARS) }) }}
      </span>
    </div>
    <p class="sub">{{ t('principalScopes') }}</p>
    <ul class="scopes">
      <li v-for="grant in operator.scopes" :key="grant">
        <Badge mono>{{ grant }}</Badge>
      </li>
    </ul>
  </AppCard>

  <AppCard v-else-if="!principalError">
    <p class="sub">{{ t('principalUnknown') }}</p>
  </AppCard>
</template>

<style scoped>
.line {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  flex-wrap: wrap;
}

.title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.key {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
}

.sub {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
}

.scopes {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  margin-top: var(--space-4);
}
</style>
