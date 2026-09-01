<script setup lang="ts">
/* Segments — gated on the capability, not on a hard-coded "not yet".
 *
 * Workstream B shipped `waxseal segments` in 0.1.5. `/v1/capabilities` reports
 * the command present, so `CommandOutput` mounts and prints the verifier's own
 * output — and not one line of this file changed when it landed, which is the
 * whole reason the gate reads the server's report instead of a constant.
 *
 * Against a wheel that lacks the command, or a server that never answered,
 * `FeatureGate` still renders the notice with the design's rotation-binding
 * sentence as context. Either way there are no placeholder segment rows: three
 * rows reading "binding holds" would be three findings nobody made.
 */

import { loadSegments } from '@/services/chains'
import FeatureGate from '@/components/app/FeatureGate.vue'
import CommandOutput from './CommandOutput.vue'

const props = defineProps<{ chainId: string }>()
</script>

<template>
  <FeatureGate feature="segments">
    <template #available>
      <CommandOutput :run="() => loadSegments(props.chainId)" />
    </template>
  </FeatureGate>
</template>
