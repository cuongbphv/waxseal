<script setup lang="ts">
import type { MintedKey } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import PillButton from '@/components/ui/PillButton.vue'
import TintPanel from '@/components/ui/TintPanel.vue'

const { t } = useI18n()

defineProps<{
  minted: MintedKey
  copied: boolean
}>()

const emit = defineEmits<{
  copy: []
  dismiss: []
}>()
</script>

<template>
  <!-- The plaintext, in the design's tint panel, held in one ref and nowhere
       else. The warning is above the value, not below it: "you cannot get
       this back" is only useful before the dismiss button is pressed. -->
  <TintPanel :title="t('mintedTitle')" role="status">
    {{ t('mintedBody') }}

    <template #aside>
      <div class="secret">
        <code class="secret-value">{{ minted.key }}</code>
        <PillButton variant="outline" @click="emit('copy')">
          {{ copied ? t('mintedCopied') : t('mintedCopy') }}
        </PillButton>
        <PillButton @click="emit('dismiss')">{{ t('mintedDismiss') }}</PillButton>
      </div>
      <p class="secret-for mono">
        {{ t('mintedFor', { label: minted.label, username: minted.username }) }}
      </p>
    </template>
  </TintPanel>
</template>

<style scoped>
.secret {
  display: flex;
  align-items: center;
  gap: var(--space-5);
  flex-wrap: wrap;
  margin-top: var(--space-6);
}

.secret-value {
  flex: 1;
  min-width: 260px;
  font-size: var(--fs-sm);
  padding: var(--space-5) var(--space-7);
  border-radius: var(--radius-control);
  border: var(--hairline) solid var(--tint-blue-border);
  background: var(--color-canvas);
  overflow-wrap: anywhere;
  user-select: all;
}

.secret-for {
  font-size: var(--fs-3xs);
  color: var(--color-ink-muted-48);
  margin-top: var(--space-4);
}
</style>
