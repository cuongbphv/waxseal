/* The column spec `DataTable` renders from.
 *
 * The design lays every table out as a CSS grid with an explicit track list
 * and a `min-width` that makes the table, not the page, scroll. Writing that
 * track list twice — once for the header strip and once for each row — is how
 * a header drifts out of alignment with its own column, so it is declared once
 * here and consumed twice from the same string.
 */

export interface Column {
  /** Slot name suffix and grid identity. */
  key: string
  /** Already translated by the caller: the table does not know about i18n. */
  label: string
  /** A CSS grid track: `84px`, `minmax(220px, 1.6fr)`. */
  track: string
  align?: 'start' | 'end'
}

export function trackList(columns: readonly Column[]): string {
  return columns.map((column) => column.track).join(' ')
}
