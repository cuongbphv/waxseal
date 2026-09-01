<script setup lang="ts">
/* A screen whose backing command may or may not exist in this build.
 *
 * Three outcomes, and none of them is a hidden screen: hiding "preflight"
 * because this build cannot run it would make "not shipped" indistinguishable
 * from "shipped and found nothing". So the screen always renders; what changes
 * is whether it renders the command's real output or a notice naming the
 * workstream that ships it.
 *
 * When the capability flips true, the `#available` slot takes over with no
 * other edit anywhere.
 */

import { computed } from 'vue'
import { FEATURES, type FeatureId } from '@/lib/features'
import { useI18n } from '@/lib/i18n'
import { featureState } from '@/services/serverFacts'
import TintPanel from '@/components/ui/TintPanel.vue'

const props = defineProps<{ feature: FeatureId }>()

const { t } = useI18n()

const descriptor = computed(() => FEATURES[props.feature])
const state = computed(() => featureState(props.feature))
</script>

<template>
  <slot v-if="state === 'available'" name="available" />
  <template v-else>
    <TintPanel :title="t(descriptor.noticeTitleKey)">
      {{ t(descriptor.noticeBodyKey) }}
      <template v-if="state === 'unknown'">
        <br />
        {{ t('serverSilent') }}
      </template>
    </TintPanel>
    <slot name="unavailable" />
  </template>
</template>
