/* Which screens are backed by something this deployment can actually run.
 *
 * Three of the design's screens were gated here because the plan said their
 * work was still coming: segments (Workstream B), preflight (E) and ledger (F).
 * B and E have since shipped, and both screens began rendering the verifier's
 * own output without a view being edited — the registry doing the job it exists
 * for. Ledger (F) is the one still waiting. None of them is special-cased in a
 * view: a screen asks this registry what state its feature is in and renders
 * accordingly, so when the command lands the screen turns into the real one on
 * its own.
 *
 * There are two independent reasons a feature can be missing, and collapsing
 * them would be the same mistake as collapsing a verdict:
 *
 *   - `command`: the waxseal build behind the server has no such subcommand.
 *     Now that B and E have shipped this is the older-wheel-behind-a-newer-
 *     portal case rather than a hypothetical one. `/v1/capabilities` answers it
 *     present-and-false, so the answer is a real three-valued one — true,
 *     false, or "the server never said".
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
    /* Workstream B shipped `waxseal segments` in 0.1.5, so against a current
     * wheel this resolves `available` and the two notice keys below never
     * render. They stay on purpose. A portal deployed in front of an OLDER
     * wheel resolves `unavailable`, and a server that never answered
     * `/v1/capabilities` — no credential in hand, or the call failed —
     * resolves `unknown`; `FeatureGate` renders the notice for both. Strings
     * unreachable only on the happy path are not unreachable, and deleting
     * them would leave those two deployments with a blank panel. */
    id: 'segments',
    command: 'segments',
    route: 'wired',
    workstream: WORKSTREAM.segments,
    noticeTitleKey: 'segmentsUnavailableTitle',
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
