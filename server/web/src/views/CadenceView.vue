<script setup lang="ts">
/* `waxseal cadence` — the only read on this server that opens no trail.
 *
 * Every input is a measurement the operator supplies, so this screen works on a
 * server holding no chains at all. Nothing is prefilled: a default would be a
 * number nobody measured, and the output would carry it with the same
 * confidence as one somebody did.
 */

import { useI18n } from '@/lib/i18n'
import { runCadenceForm } from '@/services/chains'
import PageHeader from '@/components/ui/PageHeader.vue'
import CommandForm, { type Field } from '@/components/app/CommandForm.vue'

const { t } = useI18n()

const fields: readonly Field[] = [
  { name: 'lam', label: t('cadLam'), placeholder: 'entries/s' },
  { name: 'c', label: t('cadC'), placeholder: 'cost/anchor' },
  { name: 'w', label: t('cadW'), placeholder: 'harm/entry' },
  { name: 'rho', label: t('cadRho'), placeholder: '/s' },
  { name: 'delta', label: t('cadDelta'), placeholder: 's' },
  { name: 't_max', label: t('cadTMax'), placeholder: 's' },
  { name: 'm', label: t('cadM'), placeholder: '1', optional: true },
]

function run(values: Record<string, string>) {
  return runCadenceForm(values)
}
</script>

<template>
  <PageHeader :title="t('cadTitle')" :subtitle="t('cadSub')" />
  <CommandForm :fields="fields" :run="run" />
</template>
