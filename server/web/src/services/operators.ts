/* Operators and their API keys: the server's own records, read as it reports
 * them.
 *
 * Nothing here restates the role → scope table. The server fixes it and reports
 * each operator's own `scopes`; a second copy in this client would be a
 * permission model that drifts from the one actually enforced, and a chip for a
 * scope nobody was granted is the same invention as a member count for a set
 * that does not exist.
 *
 * A minted key's plaintext passes through this module and is not kept by it.
 * There is no cache, no retry that could re-fetch it and no log line that could
 * carry it: the server stores only a SHA-256 and could not honour a second read
 * if one were attempted.
 */

import {
  ApiError,
  api,
  type ApiKeyRecord,
  type MintedKey,
  type NewOperator,
  type Operator,
  type RoleName,
} from '@/lib/api'
import type { MessageKey } from '@/lib/i18n'

export async function listOperators(): Promise<Operator[]> {
  const body = await api.operators()
  return [...body.operators].sort((left, right) => left.username.localeCompare(right.username))
}

/** Every key, revoked ones included and newest first.
 *
 * A revoked key stays in the listing on purpose: a revocation is part of the
 * history an auditor came to read, and a list that hid it would answer "which
 * credentials existed?" with a smaller set than the truth. */
export async function listKeys(username?: string): Promise<ApiKeyRecord[]> {
  const body = await api.keys(username)
  return [...body.keys].sort((left, right) => right.created_at.localeCompare(left.created_at))
}

export function createOperator(draft: NewOperator): Promise<Operator> {
  return api.createOperator(draft)
}

export function mintKey(username: string, label: string): Promise<MintedKey> {
  return api.mintKey(username, label)
}

/** Whether THIS call revoked the key. `false` means it was already revoked or
 * no key has that id — a distinct outcome from success, and never rendered as
 * one. */
export async function revokeKey(keyId: string): Promise<boolean> {
  const body = await api.revokeKey(keyId)
  return body.revoked
}

/** Initials for the avatar circle: the display name's first two words, or the
 * first two characters of whatever there is. Never empty — a blank circle in a
 * row is indistinguishable from a broken one. */
export function initialsOf(operator: Operator): string {
  const source = operator.display_name.trim() || operator.username.trim()
  const words = source.split(/[\s._-]+/).filter(Boolean)
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase()
  return source.slice(0, 2).toUpperCase()
}

/** The scope set this server reports for a role, taken from an operator that
 * actually holds it.
 *
 * `null` means no ACTIVE operator on this server holds the role, so the server
 * has reported no scope set for it — unmeasured, not empty. An inactive
 * operator is deliberately not consulted: its own scope set is empty by design
 * (a deactivation grants nothing), which says what the operator may do, not
 * what the role grants.
 */
export function scopesForRole(
  operators: readonly Operator[],
  role: RoleName,
): readonly string[] | null {
  const holder = operators.find((operator) => operator.role === role && operator.active)
  return holder ? holder.scopes : null
}

export function holdersOfRole(operators: readonly Operator[], role: RoleName): Operator[] {
  return operators.filter((operator) => operator.role === role)
}

/* ------------------------------------------------------ refusals, named */

/* The server answers a refused write with a code, and each code is a different
 * instruction to the person at the form: pick another name, pick a real role,
 * or fix the characters in the one you typed. Collapsing all three into "the
 * request failed" would leave them guessing which. */
const CREATE_OPERATOR_ERRORS: Readonly<Record<string, MessageKey>> = {
  operator_exists: 'inviteErrExists',
  invalid_role: 'inviteErrRole',
  invalid_identifier: 'inviteErrUsername',
}

const MINT_KEY_ERRORS: Readonly<Record<string, MessageKey>> = {
  no_such_operator: 'mintErrNoOperator',
}

export function createOperatorErrorKey(error: ApiError): MessageKey {
  return CREATE_OPERATOR_ERRORS[error.code] ?? 'inviteErrOther'
}

export function mintKeyErrorKey(error: ApiError): MessageKey {
  return MINT_KEY_ERRORS[error.code] ?? 'mintErrOther'
}

export function toApiError(caught: unknown): ApiError {
  return caught instanceof ApiError ? caught : new ApiError(0, 'unexpected_error', String(caught))
}
