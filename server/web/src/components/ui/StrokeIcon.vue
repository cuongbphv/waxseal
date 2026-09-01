<script setup lang="ts">
/* The design's 24×24 stroked icon, drawn from the path map in `icons.ts`.
 *
 * Always decorative: every icon in this app sits beside its own label, so
 * naming it again to a screen reader would read the label twice.
 */

import { ICON_PATHS, type IconKey } from '@/lib/icons'

withDefaults(
  defineProps<{
    name: IconKey
    size?: number
    stroke?: number
  }>(),
  { size: 17, stroke: 1.7 },
)
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="stroke"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path :d="ICON_PATHS[name]" />
  </svg>
</template>
