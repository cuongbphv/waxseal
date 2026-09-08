/* Every user-facing string in the portal, in both languages.
 *
 * The delivered design (`Waxseal Portal v2.dc.html`) ships a `strings(lang)`
 * pair and a working VI/EN toggle. The copy below is that pair, carried over
 * key for key wherever the screen it belongs to survived the honesty pass, and
 * extended with the keys the honest empty states need.
 *
 * Two things are deliberately NOT here:
 *
 *   - The design's `loginTitle` / `registerCta` / `plansTitle` families. The
 *     server has operators now, but it has no passwords — the key IS the
 *     credential — so a sign-in form would authenticate against nothing; and
 *     the paid tiers are not products. A vocabulary for either is the same
 *     invention as the screen itself.
 *   - Verdict words (`ok`, `broken`, `unverifiable`) and CLI/shell text. An
 *     operator matches those against `waxseal verify` output character for
 *     character; translating them would break the match.
 *
 * `en` is the shape of record: `MessageKey` is derived from it, so a key
 * missing from `vi` is a compile error, and a key missing from `en` cannot be
 * referenced at all.
 */

import { computed, ref, type ComputedRef } from 'vue'

import { en, type MessageKey } from './en'
import { vi } from './vi'

export type { MessageKey } from './en'

export type Lang = 'vi' | 'en'

export const LANGS: readonly Lang[] = ['vi', 'en'] as const

/* The design's toggle defaults to VI and the deployment it was drawn for is
 * Vietnamese; the choice outlives the tab because it is a preference, not a
 * credential (contrast `session.ts`). */
const STORAGE_KEY = 'waxseal.lang'
const DEFAULT_LANG: Lang = 'vi'

const TABLES: Record<Lang, Record<MessageKey, string>> = { en, vi }

function isLang(value: string | null): value is Lang {
  return value === 'vi' || value === 'en'
}

function load(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return isLang(stored) ? stored : DEFAULT_LANG
  } catch {
    return DEFAULT_LANG
  }
}

export const lang = ref<Lang>(load())

export function setLang(next: Lang): void {
  lang.value = next
  try {
    localStorage.setItem(STORAGE_KEY, next)
  } catch {
    /* Storage can be denied outright; the in-memory choice still holds. */
  }
  document.documentElement.lang = next
}

export type MessageVars = Record<string, string | number>

const PLACEHOLDER = /\{(\w+)\}/g

/** A key with no string is never rendered blank: a blank label is invisible in
 * review and ships. In development it renders as `⟦key⟧` and warns. */
function resolve(table: Record<MessageKey, string>, key: MessageKey): string {
  const value = table[key]
  if (typeof value === 'string' && value.length > 0) return value
  if (import.meta.env.DEV) {
    console.warn(`[i18n] missing message for key "${String(key)}"`)
  }
  return `⟦${String(key)}⟧`
}

export function translate(target: Lang, key: MessageKey, vars?: MessageVars): string {
  const text = resolve(TABLES[target], key)
  if (!vars) return text
  return text.replace(PLACEHOLDER, (whole, name: string) =>
    name in vars ? String(vars[name]) : whole,
  )
}

export interface I18n {
  lang: typeof lang
  t: (key: MessageKey, vars?: MessageVars) => string
  setLang: (next: Lang) => void
}

/** The reactive accessor every component uses. `t` reads `lang.value`, so a
 * toggle re-renders every string on the page without a reload. */
export function useI18n(): I18n {
  return {
    lang,
    t: (key: MessageKey, vars?: MessageVars) => translate(lang.value, key, vars),
    setLang,
  }
}

/** For the handful of places that need a computed rather than a call, such as
 * a `document.title` watcher. */
export function message(key: MessageKey, vars?: MessageVars): ComputedRef<string> {
  return computed(() => translate(lang.value, key, vars))
}
