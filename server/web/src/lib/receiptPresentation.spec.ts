import { describe, expect, it } from 'vitest'
import type { MessageKey, MessageVars } from '@/lib/i18n'
import { ApiError } from '@/lib/api'
import { panelsByChainId, verifyPanel, crossPanel } from '@/lib/receiptPresentation'
import type { ChainReceiptChecks } from '@/services/receipts'

const t = (key: MessageKey, vars?: MessageVars) =>
  vars && 'seq' in vars ? `${key}:${String(vars.seq)}` : key

function unresolved(id: string): ChainReceiptChecks {
  return {
    chainId: id,
    verify: { resolved: false, error: new ApiError(0, 'network_error', 'down') },
    crossCheck: { resolved: false, error: new ApiError(0, 'network_error', 'down') },
  }
}

describe('receiptPresentation', () => {
  it('does not fold an unresolved check into a verdict word', () => {
    const entry = unresolved('alpha')
    expect(verifyPanel(entry, t).tone).toBe('neutral')
    expect(verifyPanel(entry, t).label).toBe('serverSilent')
    expect(crossPanel(entry, t).title).toBe('down')
  })

  it('keys one panel pair per chain so a second chain cannot reuse the first', () => {
    const map = panelsByChainId([unresolved('a'), unresolved('b')], t)
    expect(map.get('a')).not.toBe(map.get('b'))
    expect(map.size).toBe(2)
  })
})
