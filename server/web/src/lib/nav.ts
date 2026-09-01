/* The sidebar, as data.
 *
 * Adding Workstream B's segments screen later has to be one entry in one of
 * these arrays — not an edit to the sidebar component, the header's breadcrumb
 * map, the router and a switch statement. The route name is the join: the
 * router reads `route` from here and the breadcrumb reads `labelKey`.
 */

import type { IconKey } from './icons'
import type { MessageKey } from './i18n'

/** Where a row's right-aligned hint number comes from. Never a literal: the
 * design's "6" and "#84" are placeholders, and a count nobody counted is the
 * thing this product exists not to print. */
export type HintSource = 'chains' | 'imports' | 'integrations' | 'none'

export interface NavItem {
  /** Matches the route name, so "which row is active" needs no second map. */
  id: string
  labelKey: MessageKey
  icon: IconKey
  hint: HintSource
}

export interface NavSection {
  titleKey: MessageKey
  items: readonly NavItem[]
}

export const PORTAL_SECTION: NavSection = {
  titleKey: 'sectionPortal',
  items: [
    { id: 'dashboard', labelKey: 'navDash', icon: 'dashboard', hint: 'chains' },
    { id: 'import', labelKey: 'navImport', icon: 'import', hint: 'imports' },
    { id: 'preflight', labelKey: 'navPreflight', icon: 'preflight', hint: 'none' },
    { id: 'consistency', labelKey: 'navCons', icon: 'proof', hint: 'none' },
    { id: 'handoff', labelKey: 'navHandoff', icon: 'handoff', hint: 'none' },
    { id: 'tickets', labelKey: 'navTickets', icon: 'tickets', hint: 'none' },
    { id: 'cadence', labelKey: 'navCadence', icon: 'cadence', hint: 'none' },
    { id: 'ledger', labelKey: 'navLedger', icon: 'ledger', hint: 'none' },
    /* No hint: counting receipts costs one request per chain, and a badge is
     * not worth N round trips. Blank is how "not counted" renders. */
    { id: 'receipts', labelKey: 'navReceipts', icon: 'receipts', hint: 'none' },
    { id: 'read-api', labelKey: 'navApi', icon: 'api', hint: 'none' },
  ],
}

/* The design's ADMIN section, minus Plans: the paid tiers in the mock are not
 * products, and a nav entry advertising them would be an invented commercial
 * offer. Users and API keys are real screens over a real operator store. */
export const ADMIN_SECTION: NavSection = {
  titleKey: 'sectionAdmin',
  items: [
    { id: 'users', labelKey: 'navUsers', icon: 'users', hint: 'none' },
    { id: 'keys', labelKey: 'navKeys', icon: 'keys', hint: 'none' },
    { id: 'benchmark', labelKey: 'navBench', icon: 'bench', hint: 'none' },
    { id: 'integrations', labelKey: 'navInt', icon: 'int', hint: 'integrations' },
    { id: 'settings', labelKey: 'navSettings', icon: 'settings', hint: 'none' },
  ],
}

export const NAV_SECTIONS: readonly NavSection[] = [PORTAL_SECTION, ADMIN_SECTION]

/** Routes that are a detail of a nav entry rather than one of their own; the
 * sidebar keeps the parent lit and the breadcrumb names the child. */
export const NAV_PARENT: Readonly<Record<string, string>> = {
  trail: 'dashboard',
}
