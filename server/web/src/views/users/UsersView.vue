<script setup lang="ts">
/* Users & Roles: the operators this server actually holds.
 *
 * The screen this replaces said there was no user system. There is one now —
 * PostgreSQL-backed operators and keys — so the card that said otherwise is
 * gone rather than softened.
 *
 * Two things are deliberately absent. The mock's "2FA" and "last active"
 * columns: the server tracks neither, and a column of em dashes is worse than
 * no column because it looks like data that failed to load. And any scope list
 * typed into this client: the role → scope table is fixed server-side and each
 * operator reports its own set, so the chips below are the server's answer. A
 * role no active operator holds shows why it has no chips instead of borrowing
 * a plausible set from somewhere.
 *
 * The Admin card keeps its line — manages the server, its operators and its
 * keys, and still cannot edit an entry, because nobody can. That is no longer
 * only doctrine: there is no `entries:edit` scope in the server's vocabulary,
 * so it is unrepresentable rather than merely unimplemented.
 */

import { computed, reactive } from 'vue'
import { useI18n } from '@/lib/i18n'
import type { NewOperator, Operator, RoleName } from '@/lib/api'
import { ROLES } from '@/content'
import { useOperators } from '@/composables/useOperators'
import type { Column } from '@/components/ui/table'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PrincipalCard from '@/components/app/PrincipalCard.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'
import { needsCredential } from '@/services/serverFacts'
import OperatorsTable from './OperatorsTable.vue'
import RolesGrid from './RolesGrid.vue'
import InviteOperatorForm from './InviteOperatorForm.vue'

const { t } = useI18n()
const { operators, creating, createError, created, invite } = useOperators()

const rows = computed<readonly Operator[]>(() => operators.data.value ?? [])

const columns = computed<Column[]>(() => [
  { key: 'who', label: t('colOperator'), track: 'minmax(260px, 1.8fr)' },
  { key: 'role', label: t('colRole'), track: '130px' },
  { key: 'created', label: t('colCreated'), track: '160px' },
  { key: 'status', label: t('colStatus'), track: '150px', align: 'end' },
])

/* The role name in the table is the server's own token (`writer`), not the
 * translated card title: it is the value an operator would type into the API,
 * and translating it would make it wrong there. The readable name rides in the
 * tooltip. */
function roleTitle(role: RoleName): string {
  const known = ROLES.find((entry) => entry.id === role)
  return known ? t(known.nameKey) : role
}

const draft = reactive<NewOperator>({
  username: '',
  display_name: '',
  email: null,
  role: 'viewer',
})

/* The form's own email field is a string; the wire wants `null` for "none".
 * An empty string would record an email address that is the empty address. */
const emailDraft = computed({
  get: () => draft.email ?? '',
  set: (value: string) => {
    draft.email = value.trim() === '' ? null : value.trim()
  },
})

async function submit(): Promise<void> {
  const ok = await invite({
    username: draft.username.trim(),
    display_name: draft.display_name.trim() || draft.username.trim(),
    email: draft.email,
    role: draft.role,
  })
  if (ok) {
    draft.username = ''
    draft.display_name = ''
    draft.email = null
    draft.role = 'viewer'
  }
}
</script>

<template>
  <PageHeader :title="t('usersTitle')" :subtitle="t('usersSub')" />

  <PrincipalCard />

  <AsyncBlock
    :pending="operators.pending.value"
    :started="operators.started.value"
    :error="operators.error.value"
    @retry="operators.run"
  >
    <template #unauthorized><AuthNeeded /></template>

    <OperatorsTable :rows="rows" :columns="columns" :role-title="roleTitle" />
    <RolesGrid :rows="rows" />
    <InviteOperatorForm
      :draft="draft"
      :email-draft="emailDraft"
      :creating="creating"
      :create-error="createError"
      :created="created"
      @update:draft="Object.assign(draft, $event)"
      @update:email-draft="emailDraft = $event"
      @submit="submit"
    />
  </AsyncBlock>

  <AuthNeeded v-if="needsCredential" />

  <p class="foot">{{ t('adminDocsWhere') }}</p>
</template>

<style scoped>
.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
