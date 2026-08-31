<script setup lang="ts">
/* Segments — gated on the capability, not on a hard-coded "not yet".
 *
 * This build has no `segments` subcommand, so `FeatureGate` renders the
 * Workstream B notice with the design's rotation-binding sentence as context.
 * There are no placeholder segment rows: three rows reading "binding holds"
 * would be three findings nobody made.
 *
 * When `/v1/capabilities` reports the command present, `CommandOutput` mounts
 * and prints the verifier's own output. Nothing else changes.
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
