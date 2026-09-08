/* The HTTP client for the waxseal server.
 *
 * Every response shape here mirrors `waxseal_server/app.py` exactly. Nothing
 * in this file computes a verdict of its own: a UI that recomputed integrity
 * would be a second verifier for an operator to reconcile against the first.
 */

import { token } from '@/lib/session'
import type { MessageKey } from '@/i18n'
import type {
  ApiKeyRecord,
  CadenceInput,
  Capabilities,
  ChainSummary,
  EntryPage,
  Head,
  ImportRecord,
  LedgerStatus,
  Meta,
  MintedKey,
  NewOperator,
  Operator,
  Outcome,
  ReceiptHead,
  ReceiptRecord,
  ReceiptsCrossCheck,
  ReceiptsVerify,
  ReconcileOutcome,
  ReportOutcome,
  Scope,
  ServerSettings,
  Whoami,
} from '@/types/api'

/* ------------------------------------------------------------------ errors */

/** An HTTP failure carried with enough detail to render a reason, never a
 * bare "something went wrong". */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly detail: string

  constructor(status: number, code: string, detail: string) {
    super(detail || code || `HTTP ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
  }

  /** 401 has its own screen: "this server requires a write credential" is a
   * different instruction to the operator than "the request failed". */
  get isUnauthorized(): boolean {
    return this.status === 401
  }

  /** 404 on head/entries/receipts means EMPTY, which is not a failure. */
  get isEmpty(): boolean {
    return this.status === 404 && this.code === 'empty'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  const authed = path.startsWith('/v1')
  const bearer = token.value
  if (authed && bearer) {
    headers.set('Authorization', `Bearer ${bearer}`)
  }
  let response: Response
  try {
    response = await fetch(path, { ...init, headers })
  } catch (cause) {
    throw new ApiError(0, 'network_error', `could not reach the server: ${String(cause)}`)
  }
  if (!response.ok) {
    let code = `http_${response.status}`
    let detail = response.statusText
    try {
      const body = (await response.json()) as { error?: string; detail?: string }
      if (typeof body.error === 'string') code = body.error
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      /* A non-JSON error body is still an error; the status carries it. */
    }
    throw new ApiError(response.status, code, detail)
  }
  return (await response.json()) as T
}

const enc = encodeURIComponent

/** A JSON body, for the four routes that write a server record. None of them
 * can touch a chain: there is no scope that grants editing an entry, so no
 * credential minted here can be given one. */
function jsonBody(body: unknown): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }
}

/* ------------------------------------------------------ endpoint catalogue */

export type HttpMethod = 'GET' | 'POST'
export type EndpointAuth = 'public' | 'bearer'

/** The Read-API screen lists this server's real endpoints, so the list has to
 * come from the module that owns the paths. A screen that retyped them would
 * publish a URL nobody had checked. `{id}` is substituted at render time. */
export interface EndpointDescriptor {
  method: HttpMethod
  /** A template. `buildEndpointPath` fills `{id}` with a real chain id. */
  path: string
  auth: EndpointAuth
  /** Key into i18n, never prose — the table is bilingual like everything else. */
  descriptionKey: MessageKey
  /** Whether the path needs a chain id before it can be followed. */
  needsChain: boolean
}

export const ENDPOINTS: readonly EndpointDescriptor[] = [
  { method: 'GET', path: '/health', auth: 'public', descriptionKey: 'epHealth', needsChain: false },
  { method: 'GET', path: '/public/v1/scope', auth: 'public', descriptionKey: 'epScope', needsChain: false },
  { method: 'GET', path: '/public/v1/chains', auth: 'public', descriptionKey: 'epChains', needsChain: false },
  { method: 'GET', path: '/public/v1/chains/{id}/head', auth: 'public', descriptionKey: 'epHead', needsChain: true },
  { method: 'GET', path: '/public/v1/chains/{id}/entries', auth: 'public', descriptionKey: 'epEntries', needsChain: true },
  { method: 'GET', path: '/public/v1/chains/{id}/receipts', auth: 'public', descriptionKey: 'epReceipts', needsChain: true },
  { method: 'GET', path: '/public/v1/chains/{id}/receipts/head', auth: 'public', descriptionKey: 'epReceiptsHead', needsChain: true },
  { method: 'GET', path: '/public/v1/chains/{id}/receipts/verify', auth: 'public', descriptionKey: 'epReceiptsVerify', needsChain: true },
  { method: 'GET', path: '/public/v1/chains/{id}/receipts/cross-check', auth: 'public', descriptionKey: 'epReceiptsCross', needsChain: true },
  { method: 'GET', path: '/public/v1/witness/{id}', auth: 'public', descriptionKey: 'epWitness', needsChain: true },
  { method: 'GET', path: '/v1/chains/{id}/summary', auth: 'bearer', descriptionKey: 'epSummary', needsChain: true },
  { method: 'GET', path: '/v1/chains/{id}/verify', auth: 'bearer', descriptionKey: 'epVerify', needsChain: true },
  { method: 'GET', path: '/v1/chains/{id}/report', auth: 'bearer', descriptionKey: 'epReport', needsChain: true },
  { method: 'POST', path: '/v1/chains/{id}/entries', auth: 'bearer', descriptionKey: 'epAppend', needsChain: true },
  { method: 'GET', path: '/v1/imports', auth: 'bearer', descriptionKey: 'epImports', needsChain: false },
  { method: 'POST', path: '/v1/witness/{id}', auth: 'bearer', descriptionKey: 'epWitnessPost', needsChain: true },
]

export function buildEndpointPath(template: string, chainId: string | null): string | null {
  if (!template.includes('{id}')) return template
  if (chainId === null) return null
  return template.replace('{id}', enc(chainId))
}

export const api = {
  health: () => request<{ status: string }>('/health'),
  meta: () => request<Meta>('/v1/meta'),
  capabilities: () => request<Capabilities>('/v1/capabilities'),

  scope: () => request<Scope>('/public/v1/scope'),

  chains: () => request<{ chains: string[] }>('/public/v1/chains'),
  summary: (id: string) => request<ChainSummary>(`/v1/chains/${enc(id)}/summary`),
  head: (id: string) => request<Head>(`/v1/chains/${enc(id)}/head`),
  entries: (id: string, cursor?: string | null) =>
    request<EntryPage>(
      `/v1/chains/${enc(id)}/entries${cursor ? `?cursor=${enc(cursor)}` : ''}`,
    ),
  verify: (id: string) => request<Outcome>(`/v1/chains/${enc(id)}/verify`),
  report: (id: string) => request<ReportOutcome>(`/v1/chains/${enc(id)}/report`),
  inspect: (id: string) => request<Outcome>(`/v1/chains/${enc(id)}/inspect`),
  exportProof: (id: string, seq: number) =>
    request<Outcome>(`/v1/chains/${enc(id)}/export-proof/${seq}`),
  segments: (id: string) => request<Outcome>(`/v1/chains/${enc(id)}/segments`),
  preflight: (id: string) => request<Outcome>(`/v1/chains/${enc(id)}/preflight`),

  /* The 0.1.5 reads. `tail` omits `n` when the caller does not choose one, so
   * the CLI's own default stays the only default. */
  tail: (id: string, n?: number) =>
    request<Outcome>(`/v1/chains/${enc(id)}/tail${n === undefined ? '' : `?n=${n}`}`),
  checkpoint: (id: string) => request<Outcome>(`/v1/chains/${enc(id)}/checkpoint`),
  consistency: (id: string, oldSeq: string, oldRoot: string) =>
    request<Outcome>(
      `/v1/chains/${enc(id)}/consistency?old_seq=${enc(oldSeq)}&old_root=${enc(oldRoot)}`,
    ),
  /* `origin` is a chain id on this server, never a path: the server resolves it
   * so a request cannot name an arbitrary file as the origin history. */
  verifyHandoff: (id: string, origin: string) =>
    request<Outcome>(`/v1/chains/${enc(id)}/verify-handoff?origin=${enc(origin)}`),
  reconcileTickets: (id: string, issuer: string, leaseSize: string, issued?: string) =>
    request<ReconcileOutcome>(
      `/v1/chains/${enc(id)}/reconcile-tickets?issuer=${enc(issuer)}` +
        `&lease_size=${enc(leaseSize)}${issued ? `&issued=${enc(issued)}` : ''}`,
    ),
  /* The one read that opens no trail, so it needs no chain to be selected. */
  cadence: (input: CadenceInput) =>
    request<Outcome>(
      `/v1/cadence?${new URLSearchParams(
        Object.entries(input).filter(([, v]) => v !== undefined && v !== '') as [
          string,
          string,
        ][],
      ).toString()}`,
    ),

  receiptsHead: (id: string) =>
    request<ReceiptHead>(`/v1/chains/${enc(id)}/receipts/head`),
  receipts: (id: string) =>
    request<{ receipts: ReceiptRecord[] }>(`/public/v1/chains/${enc(id)}/receipts`),
  receiptsVerify: (id: string) =>
    request<ReceiptsVerify>(`/public/v1/chains/${enc(id)}/receipts/verify`),
  receiptsCrossCheck: (id: string) =>
    request<ReceiptsCrossCheck>(`/public/v1/chains/${enc(id)}/receipts/cross-check`),

  witness: (id: string) =>
    request<{ checkpoints: Record<string, unknown>[] }>(`/public/v1/witness/${enc(id)}`),

  whoami: () => request<Whoami>('/v1/whoami'),
  operators: () => request<{ operators: Operator[] }>('/v1/operators'),
  createOperator: (draft: NewOperator) =>
    request<Operator>('/v1/operators', jsonBody(draft)),
  keys: (username?: string) =>
    request<{ keys: ApiKeyRecord[] }>(`/v1/keys${username ? `?username=${enc(username)}` : ''}`),
  mintKey: (username: string, label: string) =>
    request<MintedKey>('/v1/keys', jsonBody({ username, label })),
  /* `revoked` says what THIS call did. A second revoke answers false rather
   * than moving the timestamp and pretending it acted, so the caller must
   * render the two apart. */
  revokeKey: (keyId: string) =>
    request<{ revoked: boolean }>(`/v1/keys/${enc(keyId)}/revoke`, { method: 'POST' }),

  ledgerStatus: (id: string) =>
    request<LedgerStatus>(`/v1/chains/${enc(id)}/ledger-status`),

  settings: () => request<ServerSettings>('/v1/settings'),
  setSetting: (key: string, value: string) =>
    request<{ key: string; value: string; source: string }>(`/v1/settings/${enc(key)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value }),
    }),
  /* `reset` says what THIS call did: false means there was nothing stored, not
   * that it failed. A POST because this server has no DELETE anywhere. */
  resetSetting: (key: string) =>
    request<{ key: string; reset: boolean }>(`/v1/settings/${enc(key)}/reset`, {
      method: 'POST',
    }),

  imports: () => request<{ imports: ImportRecord[] }>('/v1/imports'),
  importRecord: (id: string) => request<ImportRecord>(`/v1/imports/${enc(id)}`),
  importRead: (id: string, command: string) =>
    request<Outcome>(`/v1/imports/${enc(id)}/${enc(command)}`),
  importReport: (id: string) => request<ReportOutcome>(`/v1/imports/${enc(id)}/report`),
  importEntries: (id: string) => request<EntryPage>(`/v1/imports/${enc(id)}/entries`),
  createImport: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<ImportRecord>('/v1/imports', { method: 'POST', body: form })
  },
}

