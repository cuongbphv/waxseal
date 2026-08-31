/* The receipt log, across every chain the server holds.
 *
 * Two endpoints answer two different questions and the screen shows both,
 * separately labelled. `verify` asks whether the acknowledgment log is
 * internally consistent — it stays `ok` after an edit to the trail, because
 * the log itself was not touched. `cross-check` asks whether entry `seq` still
 * carries the hash that was acknowledged for it — that is the one that catches
 * a self-consistent local rewrite. Rendering only one of them would answer a
 * question the operator did not ask.
 */

import {
  ApiError,
  api,
  type ReceiptRecord,
  type ReceiptsCrossCheck,
  type ReceiptsVerify,
} from '@/lib/api'
import { RECEIPT_FEED_LIMIT } from '@/lib/constants'
import { attemptMaybe, type Maybe } from './maybe'

/** A receipt with the chain it belongs to, which the record itself does not
 * carry because the endpoint is already per-chain. */
export interface ChainReceipt extends ReceiptRecord {
  chainId: string
}

export interface ChainReceiptChecks {
  chainId: string
  verify: Maybe<ReceiptsVerify>
  crossCheck: Maybe<ReceiptsCrossCheck>
}

export interface ReceiptFeed {
  /** Newest first, capped at the render budget. */
  records: ChainReceipt[]
  /** True when the cap hid records, so the footer can say so. */
  truncated: boolean
  checks: ChainReceiptChecks[]
}

async function recordsFor(chainId: string): Promise<ChainReceipt[]> {
  try {
    const body = await api.receipts(chainId)
    return body.receipts.map((record) => ({ ...record, chainId }))
  } catch (caught) {
    /* 404 `empty` means this chain has issued none — an answer, not a fault. */
    if (caught instanceof ApiError && caught.isEmpty) return []
    throw caught
  }
}

export async function loadReceiptFeed(chainIds: readonly string[]): Promise<ReceiptFeed> {
  const perChain = await Promise.all(
    chainIds.map(async (chainId) => ({
      chainId,
      records: await recordsFor(chainId),
      verify: await attemptMaybe(() => api.receiptsVerify(chainId)),
      crossCheck: await attemptMaybe(() => api.receiptsCrossCheck(chainId)),
    })),
  )

  const all = perChain.flatMap((chain) => chain.records)
  all.sort((left, right) => right.ts.localeCompare(left.ts) || right.receipt_seq - left.receipt_seq)

  return {
    records: all.slice(0, RECEIPT_FEED_LIMIT),
    truncated: all.length > RECEIPT_FEED_LIMIT,
    checks: perChain.map(({ chainId, verify, crossCheck }) => ({ chainId, verify, crossCheck })),
  }
}

/** The pair of checks for a single chain, for the trail screen's sidecar tab. */
export async function loadReceiptChecks(chainId: string): Promise<ChainReceiptChecks> {
  const [verify, crossCheck] = await Promise.all([
    attemptMaybe(() => api.receiptsVerify(chainId)),
    attemptMaybe(() => api.receiptsCrossCheck(chainId)),
  ])
  return { chainId, verify, crossCheck }
}
