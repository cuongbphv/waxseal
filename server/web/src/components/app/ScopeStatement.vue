<script setup lang="ts">
/* The frozen scope prose, printed verbatim.
 *
 * It comes from `waxseal.domain.report` over `/public/v1/scope`, so this
 * console cannot drift from the text an assessor cites by retyping it. It is
 * shown even when there are no chains: the statement qualifies every verdict
 * this server prints, and a qualification that disappears on an empty server
 * is not a qualification.
 *
 * `line` is the short form the CLI prints beside a verdict; `statement` is the
 * paragraph. Nothing here paraphrases either.
 */

import { useI18n } from '@/lib/i18n'
import { scope } from '@/services/serverFacts'

withDefaults(defineProps<{ form?: 'line' | 'statement' }>(), { form: 'line' })

const { t } = useI18n()
</script>

<template>
  <p v-if="scope" class="scope" :class="`scope--${form}`">
    <span class="label">{{ t('scopeLabel') }}</span>
    <span>{{ form === 'line' ? scope.line : scope.statement }}</span>
  </p>
</template>

<style scoped>
.scope {
  display: flex;
  gap: var(--space-4);
  align-items: baseline;
  flex-wrap: wrap;
  color: var(--color-ink-muted-48);
  line-height: var(--lh-body);
}

.scope--line {
  font-size: var(--fs-sm);
}

.scope--statement {
  font-size: var(--fs-xs);
}

.label {
  font-size: var(--fs-4xs);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-caps);
  text-transform: uppercase;
  color: var(--color-ink-muted-2);
}
</style>
