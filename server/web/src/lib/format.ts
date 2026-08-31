/* Pure value → display-string helpers.
 *
 * Nothing here decides a verdict, and nothing here substitutes a value for a
 * missing one: a formatter that turns `null` into "0" would be rule 5 broken
 * in the one place nobody looks. Every function that can receive `null`
 * returns it, or a caller-supplied word for it, and never a number.
 */

import { BYTES_PER_KIB, HASH_SHORT_CHARS, PAYLOAD_PREVIEW_CHARS } from './constants'

export function shortHash(hash: string, chars: number = HASH_SHORT_CHARS): string {
  return hash.length <= chars ? hash : `${hash.slice(0, chars)}…`
}

/** Binary units, because the design and the library both measure trails in
 * MiB and a trail described as 39.0 MB in one place and 37.2 MiB in another
 * is two numbers an operator has to reconcile. */
export function bytesLabel(size: number): string {
  if (size < BYTES_PER_KIB) return `${size} B`
  const kib = size / BYTES_PER_KIB
  if (kib < BYTES_PER_KIB) return `${kib.toFixed(1)} KiB`
  const mib = kib / BYTES_PER_KIB
  if (mib < BYTES_PER_KIB) return `${mib.toFixed(1)} MiB`
  return `${(mib / BYTES_PER_KIB).toFixed(2)} GiB`
}

/** Thin-space grouping, as the design writes it ("8 412"). */
export function countLabel(value: number): string {
  return value.toLocaleString('en-US').replace(/,/g, ' ')
}

/** ISO-8601 in, `YYYY-MM-DD HH:MM` out, in the operator's own zone. An
 * unparseable timestamp is returned untouched rather than replaced: the raw
 * value is a fact, and a placeholder in its place is not. */
export function tsLabel(iso: string): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ` +
    `${pad(at.getHours())}:${pad(at.getMinutes())}`
  )
}

/** The stored payload, decoded for display.
 *
 * Payloads are redacted BEFORE `payload_hash` is computed, so what comes back
 * is already the redacted form and there is nothing to reveal. Bytes that are
 * not UTF-8 are not text and are reported as such rather than mangled into
 * replacement characters that look like content. */
export function decodePayload(base64: string): string | null {
  try {
    const binary = atob(base64)
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

/** One line, for a table cell. Newlines become a visible separator so a
 * multi-line payload cannot masquerade as a short one. */
export function oneLine(text: string, limit: number = PAYLOAD_PREVIEW_CHARS): string {
  const flat = text.replace(/\s*\n\s*/g, ' ⏎ ').trim()
  return flat.length <= limit ? flat : `${flat.slice(0, limit)}…`
}
