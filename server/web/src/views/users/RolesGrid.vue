<script setup lang="ts">
import type { Operator } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { ROLES } from '@/content'
import { holdersOfRole, scopesForRole } from '@/services/operators'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'

const { t } = useI18n()

defineProps<{
  rows: readonly Operator[]
}>()
</script>

<template>
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
</template>

<style scoped>
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
</style>
