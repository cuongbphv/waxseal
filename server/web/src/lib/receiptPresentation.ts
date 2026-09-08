/* Receipt verify / cross-check panels, shared by ReceiptsView and the trail
 * sidecar tab's cousin on the receipts screen.
 *
 * Both questions stay named. `verify` asks whether the acknowledgment log is
 * internally consistent; `cross-check` asks whether entry `seq` still carries
 * the hash acknowledged for it. One function per question so a screen cannot
 * render the easy answer under the hard question's name.
 */

import type { MessageKey, MessageVars } from '@/lib/i18n'
import type { ChainReceiptChecks } from '@/services/receipts'
import { receiptsChecked } from '@/lib/measure'
import { toneOfVerdict, type Tone } from '@/lib/states'

type Translate = (key: MessageKey, vars?: MessageVars) => string

export interface ReceiptPanel {
  label: string
  tone: Tone
  title: string
}

export function verifyPanel(entry: ChainReceiptChecks, t: Translate): ReceiptPanel {
  const check = entry.verify
  if (!check.resolved) return { label: t('serverSilent'), tone: 'neutral', title: check.error.detail }
  const { verdict, checked, reason, exit_code: exit } = check.value
  return {
    label: `${verdict} · ${exit}`,
    tone: checked === null ? 'neutral' : toneOfVerdict(verdict),
    title: [receiptsChecked(checked, reason), reason].filter(Boolean).join(' · '),
  }
}

export function crossPanel(entry: ChainReceiptChecks, t: Translate): ReceiptPanel {
  const check = entry.crossCheck
  if (!check.resolved) return { label: t('serverSilent'), tone: 'neutral', title: check.error.detail }
  const { verdict, checked, reason, broken_seq: brokenSeq, exit_code: exit } = check.value
  return {
    label: `${verdict} · ${exit}`,
    tone: checked === null ? 'neutral' : toneOfVerdict(verdict),
    title: [
      receiptsChecked(checked, reason),
      reason,
      brokenSeq === null ? null : t('receiptsBrokenSeq', { seq: brokenSeq }),
    ]
      .filter(Boolean)
      .join(' · '),
  }
}

/** One panel pair per chain, keyed so a re-render does not re-derive every
 * chain's labels from the others. */
export function panelsByChainId(
  checks: readonly ChainReceiptChecks[],
  t: Translate,
): Map<string, { verify: ReceiptPanel; cross: ReceiptPanel }> {
  const map = new Map<string, { verify: ReceiptPanel; cross: ReceiptPanel }>()
  for (const entry of checks) {
    map.set(entry.chainId, {
      verify: verifyPanel(entry, t),
      cross: crossPanel(entry, t),
    })
  }
  return map
}
