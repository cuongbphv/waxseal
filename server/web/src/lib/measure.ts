/* Rendering three-valued evidence, in the only module allowed to do it.
 *
 * Rule 5: `null` is never `0`, unmeasured is never absent, unverifiable is
 * never tampered. Every one of these functions takes a value that can be
 * `null` and returns a WORD for that case — never a number, never an empty
 * string, and never a symbol that could be read as a quantity.
 */

import type { CheckSummaryJson } from './api'
import { lang, translate, type MessageKey } from './i18n'
import type { Tone } from './states'

function t(key: MessageKey, vars?: Record<string, string | number>): string {
  return translate(lang.value, key, vars)
}

/** What a rendered measurement is, kept as a triple so a caller cannot get the
 * word without the tone that must accompany it, or vice versa. */
export interface Measurement {
  /** The word or number. Never blank. */
  text: string
  /** The sentence behind it, for a `title`. */
  title: string
  tone: Tone
}

/** `dropped_writes`. The design's card prints "≥ 2"; `null` prints the word,
 * because a dropped-write count of zero and a dropped-write count nobody took
 * are opposite claims. */
export function droppedWrites(value: number | null, source: string | null): Measurement {
  if (value === null) {
    return { text: t('notMeasured'), title: t('notMeasuredWhy'), tone: 'neutral' }
  }
  return {
    text: `≥ ${value}`,
    title: source ? `${t('statDrops')} · source: ${source}` : t('statDrops'),
    tone: value > 0 ? 'unverifiable' : 'ok',
  }
}

/** A `CheckSummaryJson | null` from the report. `null` is "the sidecar was not
 * recorded", which is a different fact from "recorded and found nothing". */
export function checkSummary(summary: CheckSummaryJson | null): Measurement {
  if (summary === null) {
    return { text: t('notRecorded'), title: t('notMeasuredWhy'), tone: 'neutral' }
  }
  const counted = summary.checked > 0 ? t('sidecarChecked', { count: summary.checked }) : t('sidecarCheckedNone')
  if (summary.unverifiable) {
    return {
      text: counted,
      title: [summary.reason, ...summary.notes].filter(Boolean).join(' · ') || t('stateUnverifiableExplain'),
      tone: 'unverifiable',
    }
  }
  return {
    text: counted,
    title: [summary.reason, ...summary.notes].filter(Boolean).join(' · ') ||
      (summary.ok ? t('stateOkExplain') : t('stateBrokenExplain')),
    tone: summary.ok ? 'ok' : 'broken',
  }
}

/** The receipt checks report `checked: null` with reason `not_recorded` when
 * there is no log at all — a fourth thing beside the three verdicts. */
export function receiptsChecked(checked: number | null, reason: string | null): string {
  if (checked !== null) return t('sidecarChecked', { count: checked })
  return reason === 'not_recorded' ? t('notRecorded') : t('notMeasured')
}

/** A count this build cannot produce, in a table cell. The em dash is the
 * design's; the `title` is what stops it reading as zero. */
export function unmeasuredCell(title: string): Measurement {
  return { text: t('notApplicable'), title, tone: 'neutral' }
}
