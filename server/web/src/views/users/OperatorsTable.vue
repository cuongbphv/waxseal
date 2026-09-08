<script setup lang="ts">
import type { Operator, RoleName } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { tsLabel } from '@/lib/format'
import { initialsOf } from '@/services/operators'
import type { Column } from '@/components/ui/table'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'
import DataTable from '@/components/ui/DataTable.vue'
import StatusPill from '@/components/ui/StatusPill.vue'

const { t } = useI18n()

defineProps<{
  rows: readonly Operator[]
  columns: Column[]
  roleTitle: (role: RoleName) => string
}>()
</script>

<template>
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
</style>
