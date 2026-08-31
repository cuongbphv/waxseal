<script setup lang="ts">
/* Verbatim CLI output, with the argv that produced it above.
 *
 * The argv is not decoration. A conclusion shown without the command that
 * produced it is asking to be trusted, and this console's whole claim is that
 * it re-prints a verifier rather than being one.
 */

import { computed } from 'vue'
import { useI18n } from '@/lib/i18n'

const props = withDefaults(
  defineProps<{
    argv: readonly string[]
    stdout: string
    stderr?: string
    exitCode?: number | null
  }>(),
  { stderr: '', exitCode: undefined },
)

const { t } = useI18n()

/* Joined for display only — the array is what was executed, and nothing here
 * re-parses this string. */
const commandLine = computed(() => props.argv.join(' '))

const exitLine = computed(() => {
  if (props.exitCode === undefined) return null
  return props.exitCode === null ? t('exitNone') : t('exitLabel', { code: props.exitCode })
})
</script>

<template>
  <div class="output">
    <div class="argv">
      <span class="argv-label">{{ t('argvLabel') }}</span>
      <code class="argv-value">{{ commandLine }}</code>
    </div>
    <pre class="stdout">{{ stdout || '—' }}</pre>
    <pre v-if="stderr" class="stderr">{{ stderr }}</pre>
    <div v-if="exitLine" class="exit mono">{{ exitLine }}</div>
  </div>
</template>

<style scoped>
.output {
  background: var(--color-canvas);
  border: var(--hairline) solid var(--color-hairline);
  border-radius: var(--radius-card);
  padding: var(--space-10) var(--space-12);
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  overflow-x: auto;
}

.argv {
  display: flex;
  gap: var(--space-4);
  align-items: baseline;
  border-bottom: var(--hairline) solid var(--color-divider-soft);
  padding-bottom: var(--space-5);
  flex-wrap: wrap;
}

.argv-label {
  font-size: var(--fs-4xs);
  font-weight: var(--fw-semibold);
  letter-spacing: var(--ls-caps);
  text-transform: uppercase;
  color: var(--color-ink-muted-2);
}

.argv-value {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  overflow-wrap: anywhere;
}

.stdout,
.stderr {
  font-family: var(--font-mono);
  font-size: var(--fs-sm);
  line-height: var(--lh-mono);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.stdout {
  color: var(--color-ink);
}

.stderr {
  color: var(--status-text-unverifiable);
}

.exit {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
}
</style>
