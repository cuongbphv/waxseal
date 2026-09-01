<script setup lang="ts">
/* A read that needs numbers from the operator: fields, one Run, one output.
 *
 * The output appears only after Run. Nothing here loads on mount, unlike
 * `CommandOutput`, because there is no answer until somebody supplies the
 * inputs — and a screen that showed a result before it had them would be
 * showing a result for values it invented.
 *
 * The fields are declared as data by the calling screen, so consistency,
 * handoff and ticket reconciliation are three field lists rather than three
 * copies of this markup.
 */

import { computed, reactive, ref } from 'vue'
import type { Outcome } from '@/lib/api'
import { ApiError } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import AppCard from '@/components/ui/AppCard.vue'
import OutputPanel from '@/components/ui/OutputPanel.vue'
import PillButton from '@/components/ui/PillButton.vue'
import VerdictBadge from '@/components/ui/VerdictBadge.vue'
import AuthNeeded from '@/components/app/AuthNeeded.vue'

export interface Field {
  name: string
  label: string
  /** Shown in the field, not beside it — a placeholder is the shortest way to
   * say what shape a value has. */
  placeholder?: string
  /** A select rather than free text, for a value that must be one of a set. */
  options?: readonly string[]
  /** Optional fields do not block Run. */
  optional?: boolean
}

const props = defineProps<{
  fields: readonly Field[]
  run: (values: Record<string, string>) => Promise<Outcome>
  /** Disables Run with a reason, e.g. no chain exists to run against. */
  blockedReason?: string
}>()

const { t } = useI18n()

const values = reactive<Record<string, string>>(
  Object.fromEntries(props.fields.map((f) => [f.name, f.options?.[0] ?? ''])),
)

const outcome = ref<Outcome | null>(null)
const error = ref<ApiError | null>(null)
const pending = ref(false)

const ready = computed(
  () => !props.blockedReason && props.fields.every((f) => f.optional || values[f.name] !== ''),
)

async function submit(): Promise<void> {
  pending.value = true
  error.value = null
  try {
    outcome.value = await props.run({ ...values })
  } catch (caught) {
    outcome.value = null
    error.value =
      caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught))
  } finally {
    pending.value = false
  }
}
</script>

<template>
  <AppCard>
    <form class="form" @submit.prevent="submit">
      <div class="fields">
        <label v-for="field in fields" :key="field.name" class="field">
          <span class="label">{{ field.label }}</span>
          <select v-if="field.options" v-model="values[field.name]" class="input">
            <option v-for="option in field.options" :key="option" :value="option">
              {{ option }}
            </option>
          </select>
          <input
            v-else
            v-model="values[field.name]"
            class="input"
            :placeholder="field.placeholder"
            inputmode="text"
            autocomplete="off"
          />
        </label>
      </div>

      <div class="run">
        <PillButton type="submit" :disabled="!ready || pending">
          {{ pending ? t('running') : t('run') }}
        </PillButton>
        <span v-if="blockedReason" class="blocked">{{ blockedReason }}</span>
      </div>
    </form>
  </AppCard>

  <!-- 401 is its own instruction, not a failure: the credential is missing,
       and it is set in one place rather than on whichever screen hit the 401. -->
  <AuthNeeded v-if="error?.isUnauthorized" />
  <AppCard v-else-if="error">
    <p class="error">{{ error.message }}</p>
  </AppCard>

  <template v-if="outcome">
    <VerdictBadge :outcome="outcome" />
    <OutputPanel
      :argv="outcome.argv"
      :stdout="outcome.stdout"
      :stderr="outcome.stderr"
      :exit-code="outcome.exit_code"
    />
  </template>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: var(--space-9);
}

/* auto-fit rather than a fixed column count: the same declaration gives six
 * cadence fields three columns on a desktop and one on a phone. */
.fields {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: var(--space-7);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  min-width: 0;
}

/* Deliberately NOT uppercased, unlike the nav's section titles. These labels
 * carry Greek symbols that name the model's parameters, and `text-transform`
 * does not respect them: λ becomes Λ and ρ becomes Ρ, which reads as a Latin P.
 * A label that renames the quantity it labels is worse than an un-styled one. */
.label {
  font-size: var(--fs-3xs);
  font-weight: var(--fw-semibold);
  color: var(--color-ink-muted-48);
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

.run {
  display: flex;
  align-items: center;
  gap: var(--space-7);
  flex-wrap: wrap;
}

.blocked,
.error {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}
</style>
