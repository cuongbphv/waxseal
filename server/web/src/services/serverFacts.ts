/* What this server is, fetched once and shared: `/v1/meta`,
 * `/v1/capabilities` and the frozen scope prose.
 *
 * `capabilities` is present-and-false, never omitted, so this app can tell
 * "this build has no segments command" apart from "the server did not
 * answer". Those are different facts and they get different screens.
 */

import { computed, ref, shallowRef, watch, type ComputedRef } from 'vue'
import { ApiError, api, type Capabilities, type Meta, type Scope, type Whoami } from '@/lib/api'
import { FEATURES, resolveFeature, type FeatureId, type FeatureState } from '@/lib/features'
import { token } from '@/lib/session'

export const meta = shallowRef<Meta | null>(null)
export const metaError = shallowRef<ApiError | null>(null)
export const metaPending = ref(false)

export const capabilities = shallowRef<Capabilities | null>(null)
export const capabilitiesError = shallowRef<ApiError | null>(null)

/* The frozen scope prose, fetched once for the whole app from
 * `/public/v1/scope`. Views that have a report in hand print
 * `report.scope.statement` instead — the same text by construction — and fall
 * back to this when there is no report to print, which is exactly the case a
 * verdict most needs qualifying: an absent trail still gets a verdict, and a
 * qualification that vanishes there is not a qualification. */
export const scope = shallowRef<Scope | null>(null)
export const scopeError = shallowRef<ApiError | null>(null)

/* Who the credential currently in the token field is, from `/v1/whoami`. It
 * belongs here rather than on a screen because two screens ask the same
 * question and the answer changes for the same reason `meta` does: the operator
 * pasted a different token.
 *
 * `is_operator: false` is a SYNTHETIC principal — the bootstrap key, or a
 * server with no credential configured. It is a credential, not a person, and
 * no screen puts it in the operator table. */
export const principal = shallowRef<Whoami | null>(null)
export const principalError = shallowRef<ApiError | null>(null)

function toApiError(caught: unknown): ApiError {
  return caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught))
}

export async function loadScope(): Promise<void> {
  scopeError.value = null
  try {
    scope.value = await api.scope()
  } catch (caught) {
    scope.value = null
    scopeError.value = toApiError(caught)
  }
}

export async function loadServerFacts(): Promise<void> {
  metaPending.value = true
  metaError.value = null
  try {
    meta.value = await api.meta()
  } catch (caught) {
    meta.value = null
    metaError.value = toApiError(caught)
  } finally {
    metaPending.value = false
  }

  capabilitiesError.value = null
  try {
    capabilities.value = await api.capabilities()
  } catch (caught) {
    capabilities.value = null
    capabilitiesError.value = toApiError(caught)
  }

  principalError.value = null
  try {
    principal.value = await api.whoami()
  } catch (caught) {
    principal.value = null
    principalError.value = toApiError(caught)
  }
}

/** Three answers, not two: true, false, or null for "the server never told
 * us". A screen that read null as false would report a shipped command
 * missing. */
export function commandAvailable(name: string): boolean | null {
  const commands = capabilities.value?.commands
  if (!commands || !(name in commands)) return null
  return commands[name] === true
}

/** Whether a /v1 read can succeed at all right now. `bearer_required` with no
 * token in hand is a screen of its own, not a failed request. */
export const needsCredential: ComputedRef<boolean> = computed(
  () => (metaError.value?.isUnauthorized ?? false) || (meta.value?.write_auth === 'bearer_required' && token.value === ''),
)

export function featureState(id: FeatureId): FeatureState {
  return resolveFeature(FEATURES[id], commandAvailable)
}

/** Re-read the server facts whenever the operator supplies a new token: a
 * 401 on /v1/capabilities is a different world from an answered one. */
export function watchTokenForRefresh(): void {
  watch(token, () => {
    void loadServerFacts()
  })
}
