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
 *
 * The paragraph form is COLLAPSED, never shortened. Its wording is what an
 * assessor cites, so trimming it to fit a screen is not available — but a
 * qualification nobody finishes reading is not doing its job either, so the
 * short line is the summary and the full text is one click below it. Both come
 * from the server; neither is retyped here.
 */

import { useI18n } from '@/lib/i18n'
import { scope } from '@/services/serverFacts'

withDefaults(defineProps<{ form?: 'line' | 'statement' }>(), { form: 'line' })

const { t } = useI18n()
</script>

<template>
  <p v-if="scope && form === 'line'" class="scope scope--line">
    <span class="label">{{ t('scopeLabel') }}</span>
    <span>{{ scope.line }}</span>
  </p>

  <details v-else-if="scope" class="scope-details">
    <summary>
      <span class="label">{{ t('scopeLabel') }}</span>
      <span class="summary-line">{{ scope.line }}</span>
    </summary>
    <p class="scope scope--statement">{{ scope.statement }}</p>
  </details>
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
  margin-top: var(--space-4);
  display: block;
}

.scope-details > summary {
  display: flex;
  gap: var(--space-4);
  align-items: baseline;
  flex-wrap: wrap;
  cursor: pointer;
  color: var(--color-ink-muted-48);
  font-size: var(--fs-sm);
  line-height: var(--lh-body);
}

.summary-line {
  min-width: 0;
}

.label {
  font-size: var(--fs-4xs);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-caps);
  text-transform: uppercase;
  color: var(--color-ink-muted-2);
}
</style>
