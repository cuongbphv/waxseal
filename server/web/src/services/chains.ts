/* Chain reads, phrased as the questions the screens actually ask.
 *
 * A view asks "what is the overview row for this chain?", not "GET
 * /v1/chains/{id}/summary then GET .../verify then GET .../report". The
 * transport stays in `lib/api.ts`; the composition stays here.
 *
 * Every field that a request could not answer arrives as an explicit
 * `Unresolved`, never as a zero and never as an omitted key. A row that
 * silently rendered 0 entries for a 401 would be reporting an empty chain.
 */

import {
  ApiError,
  api,
  type AuditReportJson,
  type ChainSummary,
  type DisplayEntry,
  type CadenceInput,
  type Outcome,
  type ReconcileOutcome,
  type ReportOutcome,
} from '@/lib/api'
import { ENTRY_PAGE_RENDER_LIMIT } from '@/lib/constants'
import { attemptMaybe, type Maybe } from './maybe'

/** One row of the dashboard's trails table, and the source for the four stat
 * cards above it. */
export interface ChainOverview {
  id: string
  summary: Maybe<ChainSummary>
  verify: Maybe<Outcome>
  report: Maybe<ReportOutcome>
}

export async function listChainIds(): Promise<string[]> {
  const body = await api.chains()
  return body.chains
}

/** The three reads a dashboard row needs, in parallel per chain. `report`
 * shells out to the CLI, so it is the slow one; the row renders each cell as
 * it can rather than waiting for all three. */
export async function loadChainOverview(id: string): Promise<ChainOverview> {
  const [summary, verify, report] = await Promise.all([
    attemptMaybe(() => api.summary(id)),
    attemptMaybe(() => api.verify(id)),
    attemptMaybe(() => api.report(id)),
  ])
  return { id, summary, verify, report }
}

export async function loadChainOverviews(ids: readonly string[]): Promise<ChainOverview[]> {
  return Promise.all(ids.map((id) => loadChainOverview(id)))
}

/** The report alone, for the trail screen's sidecar cards. */
export async function loadReport(id: string): Promise<ReportOutcome> {
  return api.report(id)
}

export function reportOf(outcome: ReportOutcome | null): AuditReportJson | null {
  return outcome?.report ?? null
}

export interface EntryWindow {
  entries: DisplayEntry[]
  /** True when the server has more than this screen rendered. Never inferred
   * from a full page: the cursor is the server's own answer. */
  truncated: boolean
}

/** Entries in write order, capped at a render budget the footer discloses.
 * An empty chain answers 404 `empty`, which is not a failure. */
export async function loadEntryWindow(id: string): Promise<EntryWindow> {
  try {
    const page = await api.entries(id)
    const entries = page.entries.slice(0, ENTRY_PAGE_RENDER_LIMIT)
    return {
      entries,
      truncated: page.next_cursor !== null || page.entries.length > ENTRY_PAGE_RENDER_LIMIT,
    }
  } catch (caught) {
    if (caught instanceof ApiError && caught.isEmpty) return { entries: [], truncated: false }
    throw caught
  }
}

/** The read-only commands the trail screen's buttons run. Named as a union so a
 * view cannot invoke a command the server does not offer, and so adding one is
 * an entry here rather than a new branch in a click handler. */
export type TrailAction = 'verify' | 'report' | 'proof' | 'checkpoint' | 'tail'

export interface TrailActionDescriptor {
  id: TrailAction
  labelKey: 'runVerify' | 'runReport' | 'runProof' | 'runCheckpoint' | 'runTail'
  /** Proof and checkpoint both need an entry to be about. */
  needsHead: boolean
}

/* Every read here takes no operator input, which is why it can be a button.
 * The 0.1.5 reads that DO take input — consistency, verify-handoff,
 * reconcile-tickets, cadence — have their own screens, because a value typed
 * into a field is a measurement and belongs beside the answer it produced. */
export const TRAIL_ACTIONS: readonly TrailActionDescriptor[] = [
  { id: 'verify', labelKey: 'runVerify', needsHead: false },
  { id: 'report', labelKey: 'runReport', needsHead: false },
  { id: 'tail', labelKey: 'runTail', needsHead: false },
  { id: 'checkpoint', labelKey: 'runCheckpoint', needsHead: true },
  { id: 'proof', labelKey: 'runProof', needsHead: true },
]

export async function runTrailAction(
  id: string,
  action: TrailAction,
  headSeq: number | null,
): Promise<Outcome> {
  if (action === 'verify') return api.verify(id)
  if (action === 'report') return api.report(id)
  if (action === 'tail') return api.tail(id)
  if (action === 'checkpoint') return api.checkpoint(id)
  /* `needsHead` is enforced at the button, so reaching here without a seq is a
   * programming error rather than an operator one. */
  if (headSeq === null) throw new ApiError(0, 'empty', 'the chain has no entry to prove')
  return api.exportProof(id, headSeq)
}

/** The consistency proof between a checkpoint an operator holds and the chain
 * as it stands now. Both inputs come from the operator: a UI that filled them
 * from the same chain would be asking the chain to vouch for itself. */
export async function runConsistency(
  id: string,
  oldSeq: string,
  oldRoot: string,
): Promise<Outcome> {
  return api.consistency(id, oldSeq, oldRoot)
}

export async function runVerifyHandoff(id: string, origin: string): Promise<Outcome> {
  return api.verifyHandoff(id, origin)
}

export async function runReconcileTickets(
  id: string,
  issuer: string,
  leaseSize: string,
  issued?: string,
): Promise<ReconcileOutcome> {
  return api.reconcileTickets(id, issuer, leaseSize, issued)
}

export async function runCadence(input: CadenceInput): Promise<Outcome> {
  return api.cadence(input)
}

/** The segments command, landed by Workstream B in 0.1.5. The trail's Segments
 * tab calls this once `/v1/capabilities` reports the command present. */
export async function loadSegments(id: string): Promise<Outcome> {
  return api.segments(id)
}

/** The preflight command, landed by Workstream E in 0.1.5. The Preflight screen
 * calls this once `/v1/capabilities` reports the command present. */
export async function loadPreflight(id: string): Promise<Outcome> {
  return api.preflight(id)
}
