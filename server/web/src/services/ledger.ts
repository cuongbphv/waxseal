/* On-chain status for one trail, from the settings this server already holds.

 * A view asks "what is the ledger reading for this chain?", never
 * GET /v1/chains/{id}/ledger-status. Endpoints are configured once in
 * Settings; a caller cannot point this console's RPC client at a host of
 * their choosing.
 */

import { api, type LedgerStatus } from '@/lib/api'

export async function loadLedgerStatus(id: string): Promise<LedgerStatus> {
  return api.ledgerStatus(id)
}
