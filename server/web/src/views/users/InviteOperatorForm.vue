<script setup lang="ts">
import type { NewOperator, Operator } from '@/lib/api'
import type { ApiError } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { ROLES } from '@/content'
import { createOperatorErrorKey } from '@/services/operators'
import AppCard from '@/components/ui/AppCard.vue'
import FormField from '@/components/ui/FormField.vue'
import PillButton from '@/components/ui/PillButton.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()

const props = defineProps<{
  draft: NewOperator
  emailDraft: string
  creating: boolean
  createError: ApiError | null
  created: Operator | null
}>()

const emit = defineEmits<{
  'update:draft': [value: NewOperator]
  'update:emailDraft': [value: string]
  submit: []
}>()

function patch(partial: Partial<NewOperator>): void {
  emit('update:draft', { ...props.draft, ...partial })
}
</script>

<template>
  <AppCard>
    <h2 class="title">{{ t('inviteTitle') }}</h2>
    <p class="desc">{{ t('inviteSub') }}</p>

    <form class="form" @submit.prevent="emit('submit')">
      <FormField :label="t('inviteUsername')" :hint="t('inviteUsernameHint')">
        <input
          :value="draft.username"
          class="input mono"
          type="text"
          required
          autocomplete="off"
          spellcheck="false"
          @input="patch({ username: ($event.target as HTMLInputElement).value })"
        />
      </FormField>

      <FormField :label="t('inviteDisplay')">
        <input
          :value="draft.display_name"
          class="input"
          type="text"
          autocomplete="off"
          @input="patch({ display_name: ($event.target as HTMLInputElement).value })"
        />
      </FormField>

      <FormField :label="t('inviteEmail')">
        <input
          :value="emailDraft"
          class="input"
          type="email"
          autocomplete="off"
          @input="emit('update:emailDraft', ($event.target as HTMLInputElement).value)"
        />
      </FormField>

      <FormField :label="t('inviteRole')" narrow>
        <select
          class="input"
          :value="draft.role"
          @change="patch({ role: ($event.target as HTMLSelectElement).value as NewOperator['role'] })"
        >
          <option v-for="role in ROLES" :key="role.id" :value="role.id">
            {{ role.id }} · {{ t(role.nameKey) }}
          </option>
        </select>
      </FormField>

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
</template>

<style scoped>
.title {
  font-size: var(--fs-lg);
  font-weight: var(--fw-semibold);
}

.desc {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-2);
  line-height: var(--lh-body);
}

.form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: var(--space-6);
  align-items: start;
  margin-top: var(--space-8);
}

.submit {
  display: flex;
  align-items: flex-end;
  align-self: end;
}
</style>
