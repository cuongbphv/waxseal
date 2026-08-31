/* Which screens are backed by something this deployment can actually run.
 *
 * Three of the design's screens describe work the plan says is coming:
 * segments (Workstream B), preflight (E) and ledger (F). None of them is
 * special-cased in a view. A screen asks this registry what state its feature
 * is in and renders accordingly, so when the command lands the screen turns
 * into the real one without a view being touched.
 *
 * There are two independent reasons a feature can be missing, and collapsing
 * them would be the same mistake as collapsing a verdict:
 *
 *   - `command`: the waxseal build behind the server has no such subcommand.
 *     `/v1/capabilities` answers this present-and-false, so the answer is a
 *     real three-valued one — true, false, or "the server never said".
 *   - `endpoint`: this server exposes no route for the feature at all. That is
 *     a fact about the server, not about the CLI, and no credential or newer
 *     waxseal changes it.
 */

import { WORKSTREAM, type WorkstreamId } from './constants'
import type { MessageKey } from './i18n'

export type FeatureId = 'segments' | 'preflight' | 'ledger'

/** Available: run it. Unavailable: this build cannot, and the notice says which
 * workstream ships it. Unknown: the server did not answer — NOT "no". */
export type FeatureState = 'available' | 'unavailable' | 'unknown'

export interface FeatureDescriptor {
  id: FeatureId
  /** The `/v1/capabilities` command name, or null when no CLI command backs
   * the feature at all. */
  command: string | null
  /** Whether this server has a route wired for it. `planned` means no amount
   * of capability reporting makes the screen real. */
  route: 'wired' | 'planned'
  workstream: WorkstreamId
  noticeTitleKey: MessageKey
  noticeBodyKey: MessageKey
}

export const FEATURES: Record<FeatureId, FeatureDescriptor> = {
  segments: {
    id: 'segments',
    command: 'segments',
    route: 'wired',
    workstream: WORKSTREAM.segments,
    noticeTitleKey: 'segmentsWorkstreamTitle',
    noticeBodyKey: 'segFoot',
  },
  preflight: {
    id: 'preflight',
    command: 'preflight',
    route: 'wired',
    workstream: WORKSTREAM.preflight,
    noticeTitleKey: 'preflightUnavailableTitle',
    noticeBodyKey: 'preflightUnavailableBody',
  },
  ledger: {
    /* Workstream F has no CLI subcommand and no server route yet. When it gets
     * both, this becomes `{ command: 'ledger-status', route: 'wired' }` and the
     * screen below it starts working. */
    id: 'ledger',
    command: null,
    route: 'planned',
    workstream: WORKSTREAM.ledger,
    noticeTitleKey: 'ledgerUnavailableTitle',
    noticeBodyKey: 'ledgerUnavailableBody',
  },
}

/** Resolve a feature against what the server reported. `commandAvailable`
 * comes from the capabilities service and is itself three-valued. */
export function resolveFeature(
  descriptor: FeatureDescriptor,
  commandAvailable: (name: string) => boolean | null,
): FeatureState {
  if (descriptor.route === 'planned' || descriptor.command === null) return 'unavailable'
  const available = commandAvailable(descriptor.command)
  if (available === null) return 'unknown'
  return available ? 'available' : 'unavailable'
}
