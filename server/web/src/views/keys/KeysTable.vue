<script setup lang="ts">
import type { ApiError, ApiKeyRecord } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { KEY_ID_SHORT_CHARS } from '@/lib/constants'
import { shortHash, tsLabel } from '@/lib/format'
import type { RevokeOutcome } from '@/composables/useApiKeys'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import DataTable from '@/components/ui/DataTable.vue'
import PillButton from '@/components/ui/PillButton.vue'
import StatusPill from '@/components/ui/StatusPill.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()

defineProps<{
  rows: readonly ApiKeyRecord[]
  columns: Column[]
  revoking: string | null
  revokeError: ApiError | null
  revokeOutcome: RevokeOutcome | null
}>()

const emit = defineEmits<{
  revoke: [key: ApiKeyRecord]
}>()

function ownerLabel(row: ApiKeyRecord): string {
  return t('keyOwner', { username: row.username })
}
</script>

<template>
  <TintPanel v-if="revokeError" tone="broken" role="status">
    {{ t('revokeFailed', { detail: revokeError.detail || revokeError.code }) }}
  </TintPanel>

  <!-- `revoked: false` is an outcome, not a failure and not a success. It
       gets the neutral ground and says exactly what the server answered. -->
  <TintPanel
    v-else-if="revokeOutcome"
    :tone="revokeOutcome.revoked ? 'ok' : 'neutral'"
    role="status"
  >
    {{
      revokeOutcome.revoked
        ? t('revokeDone', { label: revokeOutcome.key.label })
        : t('revokeNothing', { label: revokeOutcome.key.label })
    }}
  </TintPanel>

  <AppCard flush scroll-x>
    <DataTable
      :columns="columns"
      :rows="rows"
      :row-key="(row) => row.key_id"
      min-width="var(--table-min-keys)"
    >
      <template #cell-key="{ row }">
        <div class="name truncate">{{ row.label }}</div>
        <div class="owner mono truncate">
          {{ ownerLabel(row) }} · {{ shortHash(row.key_id, KEY_ID_SHORT_CHARS) }}
        </div>
      </template>

      <template #cell-fingerprint="{ row }">
        <span class="mono stamp">{{ row.fingerprint }}</span>
      </template>

      <template #cell-created="{ row }">
        <span class="mono stamp">{{ tsLabel(row.created_at) }}</span>
      </template>

      <!-- `null` is "never used", which is a fact about the key. It is never
           rendered as a date and never as a blank cell. -->
      <template #cell-lastUsed="{ row }">
        <span v-if="row.last_used_at" class="mono stamp">{{ tsLabel(row.last_used_at) }}</span>
        <span v-else class="stamp muted-2" :title="t('keyNeverUsedWhy')">
          {{ t('keyNeverUsed') }}
        </span>
      </template>

      <template #cell-status="{ row }">
        <div class="status">
          <StatusPill v-if="row.active" tone="ok" :label="t('keyActive')" />
          <StatusPill
            v-else
            tone="neutral"
            :label="t('keyRevoked')"
            :title="row.revoked_at ? t('keyRevokedAt', { at: tsLabel(row.revoked_at) }) : undefined"
          />
          <PillButton
            v-if="row.active"
            variant="outline"
            :disabled="revoking === row.key_id"
            @click="emit('revoke', row)"
          >
            {{ revoking === row.key_id ? t('revoking') : t('revoke') }}
          </PillButton>
        </div>
      </template>

      <template #empty>{{ t('keysNone') }}</template>
      <template #foot>{{ t('keysFoot') }}</template>
    </DataTable>
  </AppCard>
</template>

<style scoped>
.name {
  font-size: var(--fs-sm);
  font-weight: var(--fw-semibold);
}

.owner {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-2);
  margin-top: var(--space-1);
}

.stamp {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
}

.status {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-4);
  flex-wrap: wrap;
}

/* `button.pill`, not `.pill`: PillButton and StatusPill share the class name,
 * and shrinking the status lozenge along with the control would make the word
 * inside it smaller than every other verdict word in the console. */
.status :deep(button.pill) {
  padding: var(--space-2) var(--space-7);
  font-size: var(--fs-xs);
}
</style>
