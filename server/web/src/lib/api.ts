/* The HTTP client for the waxseal server.
 *
 * Every response shape here mirrors `waxseal_server/app.py` exactly. Nothing
 * in this file computes a verdict of its own: a UI that recomputed integrity
 * would be a second verifier for an operator to reconcile against the first.
 */

import { token } from './session'
import type { MessageKey } from './i18n'

/* --------------------------------------------------------------- outcomes */

/** The five states a CLI-backed read can be in, plus the two that mean the
 * server or its argv was wrong. `verdict` is null wherever no verdict was
 * computed; `status` names which non-verdict state that was. Never collapse
 * these into a pass/fail pair. */
export type OutcomeStatus =
  | 'ok'
  | 'broken'
  | 'unverifiable'
  | 'absent'
  | 'unavailable'
  | 'usage_error'
  | 'unexpected_exit'

export type Verdict = 'ok' | 'broken' | 'unverifiable'

export interface Outcome {
  command: string
  argv: string[]
  exit_code: number | null
  verdict: Verdict | null
  status: OutcomeStatus
  stdout: string
  stderr: string
}

export interface ReportOutcome extends Outcome {
  report: AuditReportJson | null
}

/* ----------------------------------------------------------------- report */

export interface CheckSummaryJson {
  ok: boolean
  checked: number
  reason: string | null
  unverifiable: boolean
  notes: string[]
}

export interface WitnessVerdictJson {
  name: string
  status: string
  checked: number
  reason: string | null
  broken_seq: number | null
  unreadable: number
}

export interface AuditReportJson {
  chain: {
    ok: boolean
    checked: number
    broken_seq: number | null
    reason: string | null
    unverifiable_seqs: number[]
    unverifiable_note: string
  }
  completeness: {
    /** null means never measured. It is NOT a measured zero. */
    dropped_writes: number | null
    drops_source: string | null
    note: string
  }
  inventory: {
    entries_total: number
    first_ts: string | null
    last_ts: string | null
    by_payload_type: Record<string, number>
    by_fingerprint: Record<string, number>
  }
  decisions: {
    total: number
    by_decision_type: Record<string, number>
    by_oversight_mode: Record<string, number>
    oversight_unrecorded: number
    unparseable_seqs: number[]
    unparseable_note: string
  }
  anchors: CheckSummaryJson | null
  attestations: CheckSummaryJson | null
  pin: CheckSummaryJson | null
  witnesses: WitnessVerdictJson[] | null
  separation: {
    /** null means no topology was declared — not a declared degree of 0 or 1. */
    tau: number | null
    counted_authorities: { name: string; count: number }[] | null
    note: string
  }
  scope: { id: string; statement: string }
}

/* ------------------------------------------------------------- other shapes */

export interface Meta {
  version: string
  write_auth: 'bearer_required' | 'open'
  witness_auth: 'bearer_required' | 'open'
  public_read: string
  /** Whether this server has a built web bundle to serve. Optional: a server
   * predating the key omits it, and "the server did not say" is not the same
   * fact as "not built". */
  web_ui?: 'served' | 'not_built'
}

export interface Capabilities {
  commands: Record<string, boolean>
}

/** The frozen scope prose, served from `waxseal.domain.report` itself so a UI
 * copy cannot drift from the text an assessor cites. It needs no chain and no
 * credential: the statement qualifies every verdict this server prints, and a
 * qualification that disappears on an empty server is not a qualification. */
export interface Scope {
  id: string
  statement: string
  /** The one-line form the CLI prints beside a verdict, where the full
   * paragraph would bury the verdict it qualifies. */
  line: string
}

export interface EntryHeader {
  seq: number
  ts: string
  hash_version: string
  payload_type: string
  payload_hash: string
  prev_hash: string
}

export interface DisplayEntry {
  header: EntryHeader
  entry_hash: string
  payload_b64: string
}

export interface EntryPage {
  entries: DisplayEntry[]
  next_cursor: string | null
}

export interface Head {
  seq: number
  entry_hash: string
}

/** One cheap read for what the trails table needs per row, so the dashboard
 * does not page the whole chain to count it. `head: null` means the chain is
 * empty — not that the head could not be read. */
export interface ChainSummary {
  chain_id: string
  entries: number
  size_bytes: number
  head: Head | null
  receipt: ReceiptHead | null
}

export interface ReceiptHead {
  receipt_seq: number
  receipt_head: string
}

export interface ReceiptRecord {
  v: number
  seq: number
  ts: string
  entry_hash: string
  receipt_seq: number
  receipt_head: string
}

/** "Is the acknowledgment log internally consistent?" — a question about the
 * log alone. It stays `ok` after an edit to the trail, because the log itself
 * was not touched. */
export interface ReceiptsVerify {
  verdict: Verdict
  /** null with reason "not_recorded" means there is no log to check. */
  checked: number | null
  reason: string | null
  /** The RECEIPT's seq. Deliberately not the same field as cross-check's
   * `broken_seq`, which is the chain entry's. */
  broken_receipt_seq: number | null
  exit_code: number
}

/** "Does entry `seq` still carry the hash that was acknowledged for it?" — the
 * check that catches a self-consistent local rewrite, the kind that recomputes
 * `entry_hash` so plain `verify` passes. */
export interface ReceiptsCrossCheck {
  verdict: Verdict
  /** null with reason "not_recorded" means there is no log to check. */
  checked: number | null
  /** `receipt_mismatch`, or `receipt_beyond_head` for a rollback/truncation. */
  reason: string | null
  /** The CHAIN entry's seq, not the receipt's. */
  broken_seq: number | null
  exit_code: number
}

/** `reconcile-tickets --json`, parsed. The three-valued core is `measured`:
 * `false` means the issuer's data was not available this run, and `missing`
 * stays `null` rather than becoming `0`. A screen that renders "0 drops" for an
 * unmeasured reconciliation has told the one lie this command exists to
 * prevent. */
export interface Reconciliation {
  issuer: string
  measured: boolean
  verdict: Verdict
  lease_size: number
  /** `null` when nothing was measured. NOT a measured zero. */
  missing: number[] | null
  blind_spot_window: number | null
  blind_spot_missing: number[] | null
  blind_spot_bound: number
  unreadable: number[]
}

export interface ReconcileOutcome extends Outcome {
  /** `null` when the command printed no parsable report at all. */
  reconciliation: Reconciliation | null
}

/** Everything `waxseal cadence` needs. Every field is required and none has a
 * default here: a cadence computed from a number the UI chose would be advice
 * nobody measured, shown with the confidence of advice somebody did. */
export interface CadenceInput {
  lam: string
  c: string
  w: string
  rho: string
  delta: string
  t_max: string
  /** Optional — the CLI's own default is 1. */
  m?: string
}

/* ------------------------------------------------------------- settings */

/** One row of the deployment half: what this process was started with.
 *
 * A secret row has `state` and NO `value` field — the server has no field to
 * put a credential in, so this type has none either. That is deliberate: a
 * "show me the config" screen is exactly the shape of thing that leaks one. */
export interface DeploymentSetting {
  key: string
  /** The environment variable behind it, or null when it is derived. */
  env: string | null
  value?: string
  /** Secrets only: whether it is configured. Never what it is. */
  state?: 'set' | 'unset'
  secret: boolean
  editable: boolean
  reason: string
}

export type SettingKind = 'count' | 'text' | 'url' | 'address'

/** One row an operator may change. `value: null` means not configured — a
 * state, never an empty string. `source` separates "somebody chose this" from
 * "nobody has touched it", which stays true even when the two values match. */
export interface StoredSetting {
  key: string
  kind: SettingKind
  value: string | null
  source: 'stored' | 'default'
  default: string | null
  secret: false
  editable: true
}

export interface ServerSettings {
  deployment: DeploymentSetting[]
  stored: StoredSetting[]
  /** `memory` forgets on restart. Reported so a setting that vanished has its
   * reason on screen rather than in a support thread. */
  backend: 'memory' | 'postgres'
}

/** `ledger-status`, whose arguments come from the settings store.
 *
 * `configured: false` is a STATE, not an error: with no liveness address there
 * is no command to run, and `missing` names the setting that would fix it. A
 * green tick borrowed from a chain nobody queried is the failure this shape
 * exists to prevent, so `outcome` is null whenever nothing ran. */
export interface LedgerStatus {
  configured: boolean
  reason: 'no_liveness_address' | 'bond_without_writer' | null
  missing: string[]
  outcome: Outcome | null
}

export interface ImportRecord {
  import_id: string
  filename: string
  size: number
  sha256: string
  imported_at: string
  ordinal: number
}

/* --------------------------------------------- operators and their keys */

/** The four roles the server defines. It parses a role strictly and answers
 * 400 on one it does not know: defaulting an unrecognised role would be a
 * silent escalation or a silent downgrade depending on which way it fell. */
export type RoleName = 'admin' | 'auditor' | 'writer' | 'viewer'

export interface Operator {
  username: string
  display_name: string
  /** `null` means no address was recorded. It is not an empty address, and it
   * is not a blank cell. */
  email: string | null
  role: RoleName
  created_at: string
  active: boolean
  /** The scope set THIS server grants this operator, as it reports it. The
   * role → scope table is fixed server-side and is deliberately not mirrored
   * in this client: a copy would be a permission model that drifts from the
   * one actually enforced. An inactive operator's set is empty by design. */
  scopes: string[]
}

export interface ApiKeyRecord {
  key_id: string
  username: string
  label: string
  /** Already truncated server-side (`wxs_live_9f2k…`). The secret is not in
   * this record and cannot be: the store keeps only a SHA-256. */
  fingerprint: string
  created_at: string
  /** `null` means the key has never authenticated a request — a recorded fact,
   * never rendered as a date. */
  last_used_at: string | null
  revoked_at: string | null
  active: boolean
}

/** The 201 from `POST /v1/keys`, and the only place a key's plaintext exists
 * outside whatever the operator pastes it into. The server kept only its
 * SHA-256, so it cannot serve this value a second time; nothing in this client
 * stores it, re-fetches it or logs it, and there is no reveal affordance
 * anywhere because there is nothing left to reveal. */
export interface MintedKey extends ApiKeyRecord {
  key: string
  notice: string
}

/** Who the credential in hand is. `is_operator: false` marks a SYNTHETIC
 * principal — the bootstrap `WAXSEAL_API_KEY` (username `bootstrap`) or a
 * server with no credential configured at all (username `unauthenticated`).
 * Neither is a person, neither is in the operator store, and no screen may
 * render either one as a row in the operator table. */
export interface Whoami {
  username: string
  role: RoleName
  scopes: string[]
  key_id: string | null
  is_operator: boolean
}

export interface NewOperator {
  username: string
  display_name: string
  email: string | null
  role: RoleName
}

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
