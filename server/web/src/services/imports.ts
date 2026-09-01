/* Imported trails: uploaded evidence, stored read-only and never appended to.
 *
 * The design's import table has an entry count and a reason column. Neither is
 * on `ImportRecord`, so both come from running `report` against the import —
 * the same verifier the trail screen runs, against the same bytes. That makes
 * the reason the verifier's own words rather than a label this client invented.
 */

import { api, type ImportRecord, type ReportOutcome } from '@/lib/api'
import { attemptMaybe, type Maybe } from './maybe'

export interface ImportRow {
  record: ImportRecord
  /** The verifier's answer for this file: verdict, argv and the report body. */
  report: Maybe<ReportOutcome>
}

export async function listImports(): Promise<ImportRecord[]> {
  const body = await api.imports()
  /* Newest first: the file just dropped is the one being looked for. */
  return [...body.imports].sort((left, right) => right.ordinal - left.ordinal)
}

export async function loadImportRows(): Promise<ImportRow[]> {
  const records = await listImports()
  return Promise.all(
    records.map(async (record) => ({
      record,
      report: await attemptMaybe(() => api.importReport(record.import_id)),
    })),
  )
}

export async function uploadImport(file: File): Promise<ImportRecord> {
  return api.createImport(file)
}
