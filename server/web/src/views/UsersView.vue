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
import { tsLabel } from '@/lib/format'
import type { NewOperator, Operator, RoleName } from '@/lib/api'
import { ROLES } from '@/content'
import {
  createOperatorErrorKey,
  holdersOfRole,
  initialsOf,
  scopesForRole,
} from '@/services/operators'
import { useOperators } from '@/composables/useOperators'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import Badge from '@/components/ui/Badge.vue'
import DataTable from '@/components/ui/DataTable.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import TintPanel from '@/components/ui/TintPanel.vue'
import PrincipalCard from '@/components/app/PrincipalCard.vue'
import TokenField from '@/components/app/TokenField.vue'

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
    <template #unauthorized><TokenField /></template>

    <AppCard flush scroll-x>
      <div class="table-head">
        <h2>{{ t('operatorsTitle') }}</h2>
      </div>

      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="(row) => row.username"
        min-width="var(--table-min-operators)"
      >
        <template #cell-who="{ row }">
          <div class="who">
            <span class="avatar" aria-hidden="true">{{ initialsOf(row) }}</span>
            <span class="who-text">
              <span class="name truncate">{{ row.display_name }}</span>
              <span class="mono handle truncate">{{ row.username }}</span>
              <!-- `null` is not a blank cell: an em dash with the reason
                   behind it, so nobody reads a missing address as a failed
                   render. -->
              <span v-if="row.email" class="email truncate">{{ row.email }}</span>
              <span v-else class="email muted-2" :title="t('operatorNoEmail')">
                {{ t('notApplicable') }}
              </span>
            </span>
          </div>
        </template>

        <template #cell-role="{ row }">
          <Badge mono :title="roleTitle(row.role)">{{ row.role }}</Badge>
        </template>

        <template #cell-created="{ row }">
          <span class="mono stamp">{{ tsLabel(row.created_at) }}</span>
        </template>

        <template #cell-status="{ row }">
          <StatusPill
            v-if="row.active"
            tone="ok"
            :label="t('operatorActive')"
          />
          <StatusPill
            v-else
            tone="neutral"
            :label="t('operatorInactive')"
            :title="t('operatorInactiveWhy')"
          />
        </template>

        <template #empty>{{ t('operatorsNone') }}</template>
        <template #foot>{{ t('operatorsFoot') }}</template>
      </DataTable>
    </AppCard>

    <h2 class="section">{{ t('rolesTitle') }}</h2>

    <div class="grid">
      <AppCard v-for="role in ROLES" :key="role.id">
        <div class="role-head">
          <h3 class="role-name">{{ t(role.nameKey) }}</h3>
          <Badge>{{ t('roleHolders', { count: holdersOfRole(rows, role.id).length }) }}</Badge>
        </div>
        <p class="desc">{{ t(role.descriptionKey) }}</p>

        <template v-if="scopesForRole(rows, role.id)">
          <ul class="scopes">
            <li v-for="grant in scopesForRole(rows, role.id)!" :key="grant">
              <Badge mono>{{ grant }}</Badge>
            </li>
          </ul>
        </template>
        <p v-else class="desc unmeasured">{{ t('roleScopesNone') }}</p>
      </AppCard>
    </div>

    <AppCard>
      <h2 class="title">{{ t('inviteTitle') }}</h2>
      <p class="desc">{{ t('inviteSub') }}</p>

      <form class="form" @submit.prevent="submit">
        <label class="field">
          <span class="label">{{ t('inviteUsername') }}</span>
          <input
            v-model="draft.username"
            class="input mono"
            type="text"
            required
            autocomplete="off"
            spellcheck="false"
          />
          <span class="hint">{{ t('inviteUsernameHint') }}</span>
        </label>

        <label class="field">
          <span class="label">{{ t('inviteDisplay') }}</span>
          <input v-model="draft.display_name" class="input" type="text" autocomplete="off" />
        </label>

        <label class="field">
          <span class="label">{{ t('inviteEmail') }}</span>
          <input v-model="emailDraft" class="input" type="email" autocomplete="off" />
        </label>

        <label class="field field--narrow">
          <span class="label">{{ t('inviteRole') }}</span>
          <select v-model="draft.role" class="input">
            <option v-for="role in ROLES" :key="role.id" :value="role.id">
              {{ role.id }} · {{ t(role.nameKey) }}
            </option>
          </select>
        </label>

        <div class="submit">
          <PillButton type="submit" :disabled="creating || !draft.username.trim()">
            {{ creating ? t('inviteCreating') : t('inviteSubmit') }}
          </PillButton>
        </div>
      </form>
    </AppCard>

    <!-- Three refusals, three sentences. Which one it was decides what the
         person at the form does next, so they are never collapsed into "the
         request failed". -->
    <TintPanel v-if="createError" tone="broken" role="status">
      {{
        t(createOperatorErrorKey(createError), {
          username: draft.username.trim(),
          detail: createError.detail || createError.code,
        })
      }}
    </TintPanel>

    <TintPanel v-else-if="created" tone="ok" role="status">
      {{ t('inviteCreated', { username: created.username, role: created.role }) }}
    </TintPanel>
  </AsyncBlock>

  <TokenField />

  <p class="foot">{{ t('adminDocsWhere') }}</p>
</template>

<style scoped>
.table-head {
  padding: var(--space-8) var(--card-pad-x);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
}

.table-head h2 {
  font-size: var(--fs-h4);
  font-weight: var(--fw-semibold);
}

.who {
  display: flex;
  align-items: center;
  gap: var(--space-6);
  min-width: 0;
}

.avatar {
  flex: none;
  width: var(--avatar-size);
  height: var(--avatar-size);
  border-radius: var(--radius-pill);
  background: var(--tint-blue);
  color: var(--color-primary);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: var(--fs-xs);
  font-weight: var(--fw-semibold);
}

.who-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.name {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.handle {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
}

.email {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
}

.stamp {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
}

.section {
  font-size: var(--fs-h3);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-nav);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: var(--space-6);
}

.role-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-5);
  flex-wrap: wrap;
}

.title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.role-name {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-2);
  line-height: var(--lh-body);
}

.unmeasured {
  margin-top: var(--space-6);
}

.scopes {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  margin-top: var(--space-6);
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

.field--narrow {
  max-width: 320px;
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

.foot {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
