<script setup lang="ts">
/* Configuration in one place: the credential, the environment, the knobs.
 *
 * The token used to be a card on nine different screens. It lives here now, and
 * everywhere else shows a one-line pointer instead — a credential field
 * repeated twelve times is twelve places to paste a key into and twelve places
 * to forget one.
 *
 * The environment half is read-only because changing it means restarting the
 * process that holds it. Secrets in it report only whether they are SET; the
 * server sends no value and this screen has no field to render one, so it
 * cannot become a way to read a credential out of a deployment.
 */

import { computed, ref } from 'vue'
import { loadSettings, resetSetting, saveSetting } from '@/services/settings'
import type { StoredSetting } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { useAsyncData } from '@/composables/useAsyncData'
import AppCard from '@/components/ui/AppCard.vue'
import AsyncBlock from '@/components/ui/AsyncBlock.vue'
import Badge from '@/components/ui/Badge.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import TokenField from '@/components/app/TokenField.vue'

const { t } = useI18n()

const settings = useAsyncData(() => loadSettings())

/* One draft per key, seeded from the value in effect. Empty means "leave it". */
const drafts = ref<Record<string, string>>({})
const busy = ref<string | null>(null)
const failed = ref<Record<string, string>>({})

function draftFor(row: StoredSetting): string {
  return drafts.value[row.key] ?? row.value ?? ''
}

async function save(row: StoredSetting): Promise<void> {
  busy.value = row.key
  delete failed.value[row.key]
  try {
    await saveSetting(row.key, draftFor(row))
    delete drafts.value[row.key]
    await settings.run()
  } catch (caught) {
    failed.value[row.key] = caught instanceof Error ? caught.message : String(caught)
  } finally {
    busy.value = null
  }
}

async function reset(row: StoredSetting): Promise<void> {
  busy.value = row.key
  delete failed.value[row.key]
  try {
    await resetSetting(row.key)
    delete drafts.value[row.key]
    await settings.run()
  } catch (caught) {
    failed.value[row.key] = caught instanceof Error ? caught.message : String(caught)
  } finally {
    busy.value = null
  }
}

/* The in-memory store forgets on restart, so a deployment running on it is told
 * once, here, rather than discovering it after a restart. */
const forgetful = computed(() => settings.data.value?.backend === 'memory')
</script>

<template>
  <PageHeader :title="t('setTitle')" :subtitle="t('setSub')" />

  <!-- The credential, and the only place in the console that takes one. -->
  <TokenField />

  <AsyncBlock
    :pending="settings.pending.value"
    :started="settings.started.value"
    :error="settings.error.value"
    @retry="settings.run"
  >
    <template #unauthorized><span /></template>

    <template v-if="settings.data.value">
      <AppCard>
        <div class="head">
          <h2>{{ t('setStoredTitle') }}</h2>
          <StatusPill
            :tone="forgetful ? 'unverifiable' : 'ok'"
            :label="t(forgetful ? 'setBackendMemory' : 'setBackendPg')"
            :title="t(forgetful ? 'setBackendMemoryWhy' : 'setBackendPgWhy')"
          />
        </div>

        <div class="rows">
          <div v-for="row in settings.data.value.stored" :key="row.key" class="row">
            <label class="name" :for="`set-${row.key}`">
              <span class="mono">{{ row.key }}</span>
              <Badge>{{ row.source === 'stored' ? t('setStored') : t('setDefault') }}</Badge>
            </label>
            <input
              :id="`set-${row.key}`"
              class="input"
              :value="draftFor(row)"
              :placeholder="row.default ?? t('setUnset')"
              autocomplete="off"
              @input="drafts[row.key] = ($event.target as HTMLInputElement).value"
            />
            <div class="actions">
              <PillButton :disabled="busy === row.key" @click="save(row)">
                {{ t('setSave') }}
              </PillButton>
              <PillButton
                variant="outline"
                :disabled="busy === row.key || row.source !== 'stored'"
                @click="reset(row)"
              >
                {{ t('setReset') }}
              </PillButton>
            </div>
            <p v-if="failed[row.key]" class="bad">{{ failed[row.key] }}</p>
          </div>
        </div>
      </AppCard>

      <AppCard>
        <div class="head">
          <h2>{{ t('setEnvTitle') }}</h2>
          <Badge :title="t('setEnvWhy')">{{ t('setReadOnly') }}</Badge>
        </div>

        <div class="env">
          <div v-for="row in settings.data.value.deployment" :key="row.key" class="env-row">
            <span class="mono env-key">{{ row.key }}</span>
            <span class="env-env mono">{{ row.env ?? '—' }}</span>
            <!-- A secret has no value field to render. Only its state. -->
            <StatusPill
              v-if="row.secret"
              :tone="row.state === 'set' ? 'ok' : 'neutral'"
              :label="t(row.state === 'set' ? 'setIsSet' : 'setIsUnset')"
              :title="t('setSecretWhy')"
            />
            <span v-else class="mono env-value">{{ row.value }}</span>
          </div>
        </div>
      </AppCard>
    </template>
  </AsyncBlock>
</template>

<style scoped>
.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-6);
  flex-wrap: wrap;
  margin-bottom: var(--space-9);
}

h2 {
  font-size: var(--fs-h3);
  font-weight: var(--fw-semibold);
}

.rows {
  display: flex;
  flex-direction: column;
  gap: var(--space-9);
}

/* One column on a phone, label-input-actions on a wide screen. The name column
 * is fixed so the inputs line up; below the breakpoint everything stacks. */
.row {
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr) auto;
  gap: var(--space-6);
  align-items: center;
}

.name {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  font-size: var(--fs-sm);
  min-width: 0;
  flex-wrap: wrap;
}

.input {
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--color-hairline);
  background: var(--color-surface-pearl);
  outline: none;
  min-width: 0;
  font-family: var(--font-mono);
}

.input:focus {
  border-color: var(--color-primary-focus);
}

.actions {
  display: flex;
  gap: var(--space-4);
  flex-wrap: wrap;
}

.bad {
  grid-column: 1 / -1;
  font-size: var(--fs-xs);
  color: var(--color-text-destructive);
  line-height: var(--lh-body);
}

.env {
  display: flex;
  flex-direction: column;
}

/* The value column is the flexible one and the env column never wraps.
 *
 * It was the other way round — `260px 1fr auto` — and `auto` on the value let a
 * long data_dir path expand until the 1fr env column was a few pixels wide,
 * at which point `overflow-wrap: anywhere` broke WAXSEAL_SERVER_DATA_DIR into
 * one character per line. `minmax(0, 1fr)` is what lets the value shrink and
 * wrap instead of pushing its neighbours out of the row. */
.env-row {
  display: grid;
  grid-template-columns: 240px auto minmax(0, 1fr);
  gap: var(--space-6);
  align-items: baseline;
  padding: var(--row-pad-y) 0;
  border-bottom: var(--hairline) solid var(--color-divider-soft);
  font-size: var(--fs-sm);
  min-width: 0;
}

.env-row > :last-child {
  justify-self: end;
  text-align: right;
}

.env-row:last-child {
  border-bottom: 0;
}

/* Never wrapped: an env var name broken across lines is unreadable, and it is
 * the thing an operator copies into a shell. */
.env-env {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
  white-space: nowrap;
}

.env-key,
.env-value {
  overflow-wrap: anywhere;
  min-width: 0;
}

@media (max-width: 900px) {
  .row,
  .env-row {
    grid-template-columns: minmax(0, 1fr);
    gap: var(--space-4);
  }

  .env-row {
    row-gap: var(--space-2);
  }

  /* Stacked at this width, so each cell has the full row and the env name can
     wrap without colliding with anything. */
  .env-env {
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .env-row > :last-child {
    justify-self: start;
    text-align: left;
  }
}
</style>
