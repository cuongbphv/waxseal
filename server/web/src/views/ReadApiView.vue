<script setup lang="ts">
/* The public read-API, as live links.
 *
 * The point of the public read point is that a third party can check this
 * server without asking it for anything, so the endpoints are rendered as
 * links they can actually follow. The paths come from `api.ts` — the module
 * that owns them — because a table that retyped them would publish a URL
 * nobody had checked.
 *
 * The credentialled routes are listed and deliberately NOT linked: a link that
 * 401s teaches nothing.
 */

import { computed, ref, watch } from 'vue'
import { ENDPOINTS, buildEndpointPath, type EndpointDescriptor } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { useChainDirectory } from '@/composables/useChainDirectory'
import AppCard from '@/components/ui/AppCard.vue'
import Badge from '@/components/ui/Badge.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const { t } = useI18n()
const directory = useChainDirectory()

const selected = ref<string | null>(null)
watch(
  () => directory.ids.value,
  (ids) => {
    if (selected.value === null && ids?.length) selected.value = ids[0]
  },
  { immediate: true },
)

const publicEndpoints = computed(() => ENDPOINTS.filter((e) => e.auth === 'public'))
const authedEndpoints = computed(() => ENDPOINTS.filter((e) => e.auth === 'bearer'))

function href(endpoint: EndpointDescriptor): string | null {
  return buildEndpointPath(endpoint.path, selected.value)
}

function display(endpoint: EndpointDescriptor): string {
  return href(endpoint) ?? endpoint.path
}
</script>

<template>
  <PageHeader :title="t('readApi')" :subtitle="t('readApiSub')" />

  <AppCard v-if="directory.ids.value?.length">
    <label class="picker">
      <span class="picker-label">{{ t('readApiNeedsChain') }}</span>
      <select v-model="selected" class="select mono">
        <option v-for="id in directory.ids.value" :key="id" :value="id">{{ id }}</option>
      </select>
    </label>
  </AppCard>
  <AppCard v-else>
    <p class="none">{{ t('readApiNoChain') }}</p>
  </AppCard>

  <AppCard flush>
    <div class="section-head">
      <h2>{{ t('readApiPublicTitle') }}</h2>
    </div>
    <ul>
      <li v-for="endpoint in publicEndpoints" :key="endpoint.path" class="row">
        <Badge tone="accent" shape="square">{{ endpoint.method }}</Badge>
        <a
          v-if="href(endpoint)"
          class="path mono"
          :href="href(endpoint)!"
          target="_blank"
          rel="noopener"
        >{{ display(endpoint) }}</a>
        <code v-else class="path mono muted-2">{{ display(endpoint) }}</code>
        <span class="desc">{{ t(endpoint.descriptionKey) }}</span>
      </li>
    </ul>
  </AppCard>

  <AppCard flush>
    <div class="section-head">
      <h2>{{ t('readApiAuthedTitle') }}</h2>
      <p class="note">{{ t('readApiAuthedNote') }}</p>
    </div>
    <ul>
      <li v-for="endpoint in authedEndpoints" :key="`${endpoint.method}${endpoint.path}`" class="row">
        <Badge :tone="endpoint.method === 'GET' ? 'accent' : 'unverifiable'" shape="square">
          {{ endpoint.method }}
        </Badge>
        <code class="path mono">{{ display(endpoint) }}</code>
        <span class="desc">{{ t(endpoint.descriptionKey) }}</span>
      </li>
    </ul>
  </AppCard>
</template>

<style scoped>
.picker {
  display: flex;
  align-items: center;
  gap: var(--space-6);
  flex-wrap: wrap;
}

.picker-label {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
}

.select {
  font-size: var(--fs-sm);
  padding: var(--space-4) var(--space-6);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--color-hairline);
  background: var(--color-surface-pearl);
}

.none {
  font-size: var(--fs-sm);
  color: var(--color-ink-muted-48);
}

.section-head {
  padding: var(--space-8) var(--card-pad-x);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
}

.section-head h2 {
  font-size: var(--fs-h4);
  font-weight: var(--fw-semibold);
}

.note {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-2);
  line-height: var(--lh-body);
}

.row {
  display: flex;
  align-items: center;
  gap: var(--space-7);
  padding: var(--space-6) var(--card-pad-x);
  border-bottom: var(--hairline) solid var(--color-divider-soft);
  flex-wrap: wrap;
}

.path {
  font-size: var(--fs-sm);
  flex: 1;
  min-width: 220px;
  overflow-wrap: anywhere;
}

.desc {
  font-size: var(--fs-xs);
  color: var(--color-ink-muted-48);
}
</style>
