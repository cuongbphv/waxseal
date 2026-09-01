/* Every tunable number the portal uses, named once.
 *
 * A page size or a truncation length spelled inline is a number nobody can
 * find when it turns out to be wrong, and two of them drift apart silently.
 */

/** How many entries the trail screen renders before it says so. The server
 * pages with a cursor; this is a render budget, not a claim about the chain,
 * and the footer states which it is. */
export const ENTRY_PAGE_RENDER_LIMIT = 200

/** Characters of a hash shown before the ellipsis. The full value stays in a
 * `title` and behind a copy button — a truncated hash an operator cannot
 * expand is not evidence of anything. */
export const HASH_SHORT_CHARS = 12

/** One line of decoded payload in a table cell. The cell carries the full
 * decoded text in its `title`. */
export const PAYLOAD_PREVIEW_CHARS = 160

/** Receipt rows rendered on the receipts screen, newest first. */
export const RECEIPT_FEED_LIMIT = 100

/** Bytes per binary step, for the size column. The trails the server holds are
 * measured in MiB, and the design writes "37.2 MiB", not "39.0 MB". */
export const BYTES_PER_KIB = 1024

/** The two usernames the server reports for a principal that has no record
 * behind it: the bootstrap `WAXSEAL_API_KEY`, and a deployment with no
 * credential configured at all. `whoami` marks both `is_operator: false`; these
 * names are what lets a screen say WHICH of the two it is looking at instead of
 * printing one notice for both. Neither is ever rendered as a person. */
export const SYNTHETIC_BOOTSTRAP = 'bootstrap'
export const SYNTHETIC_OPEN = 'unauthenticated'

/** How many characters of a `key_id` identify a key on screen. The id is a
 * public handle, not a secret, but the whole 32 is noise in a sentence. */
export const KEY_ID_SHORT_CHARS = 8

/** The set of workstream names the plan uses, so a notice cannot invent one. */
export const WORKSTREAM = {
  segments: 'B',
  preflight: 'E',
  ledger: 'F',
} as const

export type WorkstreamId = (typeof WORKSTREAM)[keyof typeof WORKSTREAM]
