<script setup lang="ts">
import { useI18n } from '@/lib/i18n'
import PageHeader from '@/components/ui/PageHeader.vue'
import PillButton from '@/components/ui/PillButton.vue'
import { useRouter } from 'vue-router'

const { t } = useI18n()
const router = useRouter()
</script>

<template>
  <PageHeader :title="t('notFoundTitle')" :subtitle="t('notFoundBody')">
    <template #actions>
      <PillButton @click="router.push({ name: 'dashboard' })">{{ t('navDash') }}</PillButton>
    </template>
  </PageHeader>
</template>
