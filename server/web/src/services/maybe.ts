/* A per-field result, so one failed request does not blank a whole screen.
 *
 * A dashboard row needs three reads and any of them can 401 on its own. The
 * alternatives are both wrong: throwing loses the two that succeeded, and
 * substituting a default publishes a number nobody measured. `Maybe` keeps the
 * failure attached to the one cell it belongs to, with the reason, so the cell
 * can say why it is blank instead of looking empty.
 *
 * This is NOT the same three-valued distinction as rule 5. `Unresolved` means
 * "this client could not obtain the value"; a `null` INSIDE a resolved value
 * means "the server measured nothing". A screen must not render them alike.
 */

import { ApiError } from '@/lib/api'

export interface Resolved<T> {
  readonly resolved: true
  readonly value: T
}

export interface Unresolved {
  readonly resolved: false
  readonly error: ApiError
}

export type Maybe<T> = Resolved<T> | Unresolved

export function resolved<T>(value: T): Resolved<T> {
  return { resolved: true, value }
}

export function unresolved(caught: unknown): Unresolved {
  return {
    resolved: false,
    error: caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught)),
  }
}

export async function attemptMaybe<T>(fn: () => Promise<T>): Promise<Maybe<T>> {
  try {
    return resolved(await fn())
  } catch (caught) {
    return unresolved(caught)
  }
}

/** Read a resolved value, or `null` when the request failed. Callers that use
 * this MUST render the failure some other way — it is for arithmetic over a
 * set of rows, not for display. */
export function valueOrNull<T>(maybe: Maybe<T>): T | null {
  return maybe.resolved ? maybe.value : null
}
