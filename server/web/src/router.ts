import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import type { MessageKey } from '@/lib/i18n'

/* Path history is safe here, and the hash workaround is not needed: the
 * FastAPI app mounts the built bundle behind `SpaStaticFiles`
 * (`waxseal_server/app.py`), which answers an unmatched non-API path with
 * `index.html`, so a refresh of `/trails/default` reaches this router. The
 * same class deliberately does NOT do that under an API prefix — an unmatched
 * `/v1/...` or `/public/...` stays a real 404 rather than being handed a web
 * page, which would turn "no such endpoint" into a parse error downstream.
 * Both halves are covered by `tests/test_static_ui.py`.
 *
 * Route NAMES are the join with `lib/nav.ts`: the sidebar lights the row whose
 * `id` equals the active route name, and the header reads `meta.crumbKey`.
 * Adding a screen is an entry here plus an entry there — never a third edit in
 * a layout component.
 */

declare module 'vue-router' {
  interface RouteMeta {
    crumbKey: MessageKey
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    meta: { crumbKey: 'navDash' },
    component: () => import('@/views/DashboardView.vue'),
  },
  {
    /* The tab is in the URL so an operator can send someone the sidecar tab of
     * a specific trail, which is the whole reason anyone links to this screen. */
    path: '/trails/:id/:tab?',
    name: 'trail',
    meta: { crumbKey: 'navTrail' },
    component: () => import('@/views/TrailView.vue'),
    props: true,
  },
  {
    path: '/import',
    name: 'import',
    meta: { crumbKey: 'navImport' },
    component: () => import('@/views/ImportView.vue'),
  },
  {
    path: '/preflight',
    name: 'preflight',
    meta: { crumbKey: 'navPreflight' },
    component: () => import('@/views/PreflightView.vue'),
  },
  {
    path: '/ledger',
    name: 'ledger',
    meta: { crumbKey: 'navLedger' },
    component: () => import('@/views/LedgerView.vue'),
  },
  {
    path: '/receipts',
    name: 'receipts',
    meta: { crumbKey: 'navReceipts' },
    component: () => import('@/views/ReceiptsView.vue'),
  },
  {
    path: '/read-api',
    name: 'read-api',
    meta: { crumbKey: 'navApi' },
    component: () => import('@/views/ReadApiView.vue'),
  },
  {
    path: '/users',
    name: 'users',
    meta: { crumbKey: 'navUsers' },
    component: () => import('@/views/UsersView.vue'),
  },
  {
    path: '/keys',
    name: 'keys',
    meta: { crumbKey: 'navKeys' },
    component: () => import('@/views/KeysView.vue'),
  },
  {
    path: '/benchmark',
    name: 'benchmark',
    meta: { crumbKey: 'navBench' },
    component: () => import('@/views/BenchmarkView.vue'),
  },
  {
    path: '/integrations',
    name: 'integrations',
    meta: { crumbKey: 'navInt' },
    component: () => import('@/views/IntegrationsView.vue'),
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    meta: { crumbKey: 'navNotFound' },
    component: () => import('@/views/NotFoundView.vue'),
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})
