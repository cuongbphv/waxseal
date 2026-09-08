<script setup lang="ts">
import type { Operator } from '@/lib/api'
import type { ApiError } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { mintKeyErrorKey } from '@/services/operators'
import AppCard from '@/components/ui/AppCard.vue'
import FormField from '@/components/ui/FormField.vue'
import PillButton from '@/components/ui/PillButton.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()

defineProps<{
  operators: readonly Operator[] | null
  owner: string
  label: string
  canMint: boolean
  minting: boolean
  mintError: ApiError | null
}>()

const emit = defineEmits<{
  'update:owner': [value: string]
  'update:label': [value: string]
  mint: []
}>()
</script>

<template>
  <AppCard>
    <h2 class="title">{{ t('mintTitle') }}</h2>

    <p v-if="operators && !operators.length" class="desc">
      {{ t('mintNoOperators') }}
    </p>

    <form class="form" @submit.prevent="emit('mint')">
      <FormField :label="t('mintOperator')">
        <select
          class="input mono"
          :value="owner"
          @change="emit('update:owner', ($event.target as HTMLSelectElement).value)"
        >
          <option v-for="operator in operators ?? []" :key="operator.username" :value="operator.username">
            {{ operator.username }} · {{ operator.role }}
          </option>
        </select>
      </FormField>

      <FormField :label="t('mintLabel')" :hint="t('mintLabelHint')">
        <input
          class="input"
          type="text"
          autocomplete="off"
          spellcheck="false"
          :value="label"
          @input="emit('update:label', ($event.target as HTMLInputElement).value)"
        />
      </FormField>

      <div class="submit">
        <PillButton type="submit" :disabled="!canMint">
          {{ minting ? t('mintMinting') : t('mintSubmit') }}
        </PillButton>
      </div>
    </form>
  </AppCard>

  <TintPanel v-if="mintError" tone="broken" role="status">
    {{
      t(mintKeyErrorKey(mintError), {
        username: owner,
        detail: mintError.detail || mintError.code,
      })
    }}
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

.submit {
  display: flex;
  align-items: flex-end;
  align-self: end;
}
</style>
