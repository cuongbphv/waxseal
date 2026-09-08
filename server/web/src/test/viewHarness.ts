import { mount, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'

export const viewStubs = {
  RouterLink: { template: '<a><slot /></a>' },
  PageHeader: true,
  PrincipalCard: true,
  AsyncBlock: { template: '<div class="async"><slot /></div>' },
  AppCard: { template: '<div class="card"><slot /></div>' },
  DataTable: true,
  TintPanel: { template: '<section class="tint"><slot /><slot name="aside" /></section>' },
  Badge: true,
  PillButton: true,
  StatusPill: true,
}

export function mountView(component: Component): VueWrapper {
  return mount(component, { global: { stubs: viewStubs } })
}
