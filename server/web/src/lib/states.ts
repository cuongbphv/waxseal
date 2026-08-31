/* The vocabulary of states, in one place so no screen can invent a shorter one.
 *
 * Two collapses killed two production systems: an unknown schema version read
 * as "tampered" (migration 060), and an unknown version read as a fatal error
 * (beads v1.2.2). Both are the same move — forcing a three-valued evidential
 * state into a two-valued one. This module exists so that move has nowhere to
 * happen: every state has its own label, its own sentence, and its own tone,
 * and the word alone carries the meaning if the colour never renders.
 *
 * Adding a status here is the whole change. No view switches on a status
 * string; they all render whatever this map returns, so a state this build has
 * never seen still arrives with a word rather than as a blank cell.
 */

import type { MessageKey } from './i18n'
import type { OutcomeStatus } from './api'

/* Four tones, not five: `absent`, `unavailable` and everything unrecognised
 * share the neutral one, because none of them is a finding about content and
 * giving them a colour of their own would imply one. */
export type Tone = 'ok' | 'broken' | 'unverifiable' | 'neutral'

export interface StateStyle {
  /** The word. Colour is redundant to this, never a substitute for it. It is
   * deliberately untranslated: an operator matches it against the CLI's own
   * output. */
  label: string
  /** One line, stating what the state does and does not claim. */
  explanationKey: MessageKey
  /** A paragraph, where the line is not enough. Absent means the line is the
   * whole story. */
  detailKey?: MessageKey
  tone: Tone
}

export const STATES: Record<OutcomeStatus, StateStyle> = {
  ok: {
    label: 'ok',
    explanationKey: 'stateOkExplain',
    tone: 'ok',
  },
  broken: {
    label: 'broken',
    explanationKey: 'stateBrokenExplain',
    tone: 'broken',
  },
  unverifiable: {
    label: 'unverifiable',
    explanationKey: 'stateUnverifiableExplain',
    detailKey: 'stateUnverifiableDetail',
    tone: 'unverifiable',
  },
  absent: {
    label: 'absent',
    explanationKey: 'stateAbsentExplain',
    detailKey: 'stateAbsentDetail',
    tone: 'neutral',
  },
  unavailable: {
    label: 'unavailable',
    explanationKey: 'stateUnavailableExplain',
    detailKey: 'stateUnavailableDetail',
    tone: 'neutral',
  },
  usage_error: {
    label: 'usage error',
    explanationKey: 'stateUsageErrorExplain',
    tone: 'neutral',
  },
  unexpected_exit: {
    label: 'unexpected exit',
    explanationKey: 'stateUnexpectedExitExplain',
    tone: 'neutral',
  },
}

export function stateOf(status: OutcomeStatus | string): StateStyle {
  return (
    STATES[status as OutcomeStatus] ?? {
      label: status,
      explanationKey: 'stateUnknownExplain',
      tone: 'neutral',
    }
  )
}

/** The verdict words map onto the same tones, for the places that hold a bare
 * `Verdict` rather than a whole outcome (the receipt checks). */
export function toneOfVerdict(verdict: 'ok' | 'broken' | 'unverifiable'): Tone {
  return STATES[verdict].tone
}
