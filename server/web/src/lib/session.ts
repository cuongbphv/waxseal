/* The operator's bearer token, held for this browser tab only.
 *
 * sessionStorage, not localStorage: a credential that outlives the tab is a
 * credential nobody remembers leaving behind. It is sent on `/v1` requests
 * only — the public read point takes no credential and has no write route to
 * take one for.
 */

import { ref, watch } from 'vue'

const KEY = 'waxseal.api_token'

function load(): string {
  try {
    return sessionStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

export const token = ref<string>(load())

watch(token, (value) => {
  try {
    if (value) sessionStorage.setItem(KEY, value)
    else sessionStorage.removeItem(KEY)
  } catch {
    /* Storage can be denied outright; the in-memory token still works. */
  }
})

export function setToken(value: string): void {
  token.value = value.trim()
}

export function clearToken(): void {
  token.value = ''
}
