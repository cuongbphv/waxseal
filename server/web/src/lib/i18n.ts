/* Every user-facing string in the portal, in both languages.
 *
 * The delivered design (`Waxseal Portal v2.dc.html`) ships a `strings(lang)`
 * pair and a working VI/EN toggle. The copy below is that pair, carried over
 * key for key wherever the screen it belongs to survived the honesty pass, and
 * extended with the keys the honest empty states need.
 *
 * Two things are deliberately NOT here:
 *
 *   - The design's `loginTitle` / `registerCta` / `plansTitle` families. The
 *     server has operators now, but it has no passwords — the key IS the
 *     credential — so a sign-in form would authenticate against nothing; and
 *     the paid tiers are not products. A vocabulary for either is the same
 *     invention as the screen itself.
 *   - Verdict words (`ok`, `broken`, `unverifiable`) and CLI/shell text. An
 *     operator matches those against `waxseal verify` output character for
 *     character; translating them would break the match.
 *
 * `en` is the shape of record: `MessageKey` is derived from it, so a key
 * missing from `vi` is a compile error, and a key missing from `en` cannot be
 * referenced at all.
 */

import { computed, ref, type ComputedRef } from 'vue'

export type Lang = 'vi' | 'en'

export const LANGS: readonly Lang[] = ['vi', 'en'] as const

/* The design's toggle defaults to VI and the deployment it was drawn for is
 * Vietnamese; the choice outlives the tab because it is a preference, not a
 * credential (contrast `session.ts`). */
const STORAGE_KEY = 'waxseal.lang'
const DEFAULT_LANG: Lang = 'vi'

const en = {
  /* ------------------------------------------------------------- chrome */
  sectionPortal: 'Portal',
  sectionAdmin: 'Admin',
  sidebarServer: 'Server {version}',
  sidebarServerUnknown: 'Server · version unknown',
  headPill: 'head {hash}',
  headPillNoChain: 'head · no chain selected',
  headPillEmpty: 'head · chain is empty',
  readOnly: 'read-only',
  readOnlyTitle:
    'This console never appends, edits, reorders or repairs a chain entry — no credential it can hold grants that, because no such scope exists. It does write three things that are not a chain: an imported trail, stored as read-only evidence; an operator record; and an API key.',
  langVi: 'VI',
  langEn: 'EN',
  motto: 'Verify reports — never edits, never deletes.',
  skipToContent: 'Skip to content',
  ledgerNoChain: 'No chain on this server to check on-chain.',
  ledgerNotConfigured: 'Ledger not configured',
  ledgerMissing: 'Set {keys} in Settings to query it.',
  ledgerQueried: 'queried',
  ledgerQueriedWhy: 'Read from the configured RPC endpoints, not assumed.',
  navSettings: 'Settings',
  setTitle: 'Settings',
  setSub: 'The credential, the environment, and the knobs you can change.',
  setStoredTitle: 'Server settings',
  setEnvTitle: 'Deployment',
  setEnvWhy: 'Set in the process environment. Changing these means restarting the server.',
  setReadOnly: 'read-only',
  setStored: 'stored',
  setDefault: 'default',
  setUnset: 'not configured',
  setSave: 'Save',
  setReset: 'Reset',
  setIsSet: 'set',
  setIsUnset: 'unset',
  setSecretWhy: 'A credential. The server reports only whether it is set, never its value.',
  setBackendMemory: 'in memory',
  setBackendMemoryWhy: 'No database configured, so these settings are lost on restart.',
  setBackendPg: 'PostgreSQL',
  setBackendPgWhy: 'Stored in the database and kept across restarts.',
  authNeededTitle: 'This read needs a credential',
  authNeededBody: 'The API token is set once, in Settings.',
  authNeededLink: 'Go to Settings',
  /* ------------------------------------------- 0.1.5 reads with inputs */
  run: 'Run',
  running: 'Running…',
  runTail: 'Tail',
  runCheckpoint: 'Checkpoint',

  navCons: 'Consistency',
  navHandoff: 'Handoff',
  navTickets: 'Tickets',
  navCadence: 'Cadence',

  consTitle: 'Consistency',
  consSub: 'Does a checkpoint you already hold still sit on this chain?',
  consChain: 'Chain',
  consOldSeq: 'Old seq',
  consOldRoot: 'Old root',
  consRootShape: '64 hex chars',
  consNoChains: 'No chains on this server yet.',

  handoffTitle: 'Handoff',
  handoffSub: 'Check the delegate trail\u2019s bindings against the origin\u2019s history.',
  handoffDelegate: 'Delegate trail',
  handoffOrigin: 'Origin trail',
  handoffNoChains: 'No chains on this server yet.',

  ticketsTitle: 'Tickets',
  ticketsSub: 'Reconcile issued admission tickets against the trail.',
  ticketsChain: 'Chain',
  ticketsIssuer: 'Issuer',
  ticketsLease: 'Lease size',
  ticketsIssued: 'Issued range',
  ticketsNoChains: 'No chains on this server yet.',
  ticketsUnmeasured: 'Unmeasured \u2014 no issuer data this run',
  ticketsNoDrops: 'No drop detected',
  ticketsDropped: '{n} ticket(s) missing',
  ticketsBlindSpot: 'Blind spot bound {bound}, lease {lease}.',

  cadTitle: 'Cadence',
  cadSub: 'Cost-optimal anchoring interval from your own measurements.',
  cadLam: 'Rate \u03bb',
  cadC: 'Anchor cost',
  cadW: 'Harm per entry',
  cadRho: 'Discount \u03c1',
  cadDelta: 'Anchor latency',
  cadTMax: 'Max latency',
  cadM: 'Multiplier',
  navOpen: 'Open navigation',
  navClose: 'Close navigation',

  /* --------------------------------------------------------------- nav */
  navDash: 'Dashboard',
  navImport: 'Import',
  navPreflight: 'Preflight',
  navLedger: 'Ledger',
  navReceipts: 'Receipts',
  navApi: 'Read-API',
  navUsers: 'Users & Roles',
  navKeys: 'API keys',
  navBench: 'Benchmark',
  navInt: 'Integrations',
  navTrail: 'Trail',
  navNotFound: 'Not found',

  /* ------------------------------------------------------ shared states */
  loading: 'reading…',
  loadFailed: 'The request failed: {detail}',
  retry: 'Try again',
  notMeasured: 'not measured',
  notRecorded: 'not recorded',
  notConfigured: 'not configured',
  notDetected: 'not detected from here',
  notApplicable: '—',
  unavailableHere: 'unavailable in this build',
  serverSilent: 'the server did not say',
  nothingYet: 'nothing yet',
  noChains: 'This server holds no chains yet. Append one and it appears here.',
  authNeeded: 'This server requires a bearer credential for /v1 reads.',
  authOpen: 'No credential required: no key minted, WAXSEAL_API_KEY unset. Minting the first key closes it.',
  authUnknown: 'The server has not said whether /v1 reads need a credential.',
  authField: 'WAXSEAL_API_KEY',
  authApply: 'Use this token',
  authClear: 'Forget token',
  authHint:
    'Held for this browser tab only. It is sent on /v1 requests; the public read-API takes no credential.',

  /* Rule 5, rendered. `null` is a third value and says so. */
  notMeasuredWhy: '“not measured” is not zero. No measurement was taken, so none is reported.',
  unverifiableWhy: 'unverifiable ≠ tampered',

  /* --------------------------------------------------------- dashboard */
  statChains: 'Chains',
  statChainsSub: '{count} on this server',
  statVerdict: 'Verdict',
  statDropsTitle: 'Dropped writes',
  statDrops: 'measured minimum (.drops)',
  statDropsPartial: 'measured on {measured} of {total} chains',
  statDropsNone: 'no chain reported a measurement',
  statAnchor: 'Latest anchor',
  statAnchorChecked: '{checked} anchored checkpoints checked',
  statAnchorNone: 'no chain recorded an anchors sidecar',
  trailsTitle: 'Per-project trails',
  colChain: 'chain',
  colSegments: 'segments',
  colEntries: 'entries',
  colSize: 'size',
  colVerdict: 'verdict',
  colAnchor: 'last anchor',
  segmentsNotCountedTitle: 'No segment count was taken for this row. Open the trail’s Segments tab to run the check.',
  chainEntriesUnknown: 'entry count unavailable: {detail}',
  chainEmpty: 'empty chain — no entries appended yet',
  chainHead: 'head seq {seq}',

  /* ------------------------------------------------------------- trail */
  backToDashboard: '← Dashboard',
  runVerify: 'Verify',
  runReport: 'Report',
  runProof: 'Export proof',
  runProofEmptyTitle: 'There is no entry to prove: the chain is empty.',
  tabEntries: 'Entries',
  tabSegments: 'Segments',
  tabSidecars: 'Sidecars',
  tabOutput: 'Output',
  colTs: 'ts',
  colPayloadType: 'payload_type',
  colPayload: 'payload (redacted)',
  colEntryHash: 'entry_hash',
  entriesFoot: 'Payloads are redacted before hashing.',
  entriesFootWhy: 'Redaction runs before payload_hash, so the cleartext never reached this server.',
  entriesEmpty: 'No entries on this chain yet.',
  entriesMore: 'Showing the first {shown} entries. The chain has more.',
  segFoot: 'Rotation at 16 MiB · segments join via the seq-0 rotation binding.',
  segmentsUnavailableTitle: 'This build cannot verify sealed segments',
  verifyFoot: 'Output + exit code from the waxseal CLI, verbatim.',
  argvLabel: 'argv',
  exitLabel: 'exit {code}',
  exitNone: 'no exit code: the command never ran',
  scopeLabel: 'Scope',

  /* ---------------------------------------------------------- sidecars */
  sidecarAttest: '.attest',
  sidecarAttestDesc: 'Forward-secure seals + FssAgg accumulator',
  sidecarAnchors: '.anchors',
  sidecarAnchorsDesc: 'Anchored checkpoints · TSA + witness',
  sidecarDrops: '.drops',
  sidecarDropsDesc: 'Dropped writes — measured minimum',
  sidecarPin: '.pin',
  sidecarPinDesc: 'Verifier-side pin state (SPEC §13)',
  sidecarReceiptsVerify: '.receipts · verify',
  sidecarReceiptsVerifyDesc:
    'Is the acknowledgment log internally consistent? A question about the log alone.',
  sidecarReceiptsCross: '.receipts · cross-check',
  sidecarReceiptsCrossDesc:
    'Does entry seq still carry the hash that was acknowledged for it? Catches a self-consistent local rewrite.',
  sidecarSealkey: '.sealkey',
  sidecarSealkeyDesc: 'One-way epoch key · A₀ escrowed off-box',
  sidecarSealkeyStatus: 'no server endpoint reads this sidecar',
  sidecarChecked: '{count} checked',
  sidecarCheckedNone: 'nothing checked',

  /* ------------------------------------------------------------ import */
  importTitle: 'Import a trail',
  importSub: 'An imported trail is evidence — stored read-only, never appended to.',
  dropTitle: 'Drop trail.jsonl / trail.db here',
  dropSub: 'with .attest · .anchors · .drops · .receipts sidecars if present',
  chooseFile: 'Choose file',
  imported: 'Imported',
  importUploading: 'uploading {name}…',
  importFailed: 'Upload failed: {detail}',
  importNone: 'Nothing imported yet.',
  colImportSource: 'source',
  colImportReason: 'reason',
  importSourceUpload: 'uploaded {at} · {size}',

  /* --------------------------------------------------------- preflight */
  preflightTitle: 'Preflight',
  preflightSub: 'Which attacker tier the current configuration stops.',
  preflightUnavailableTitle: 'This build cannot determine a deployment’s tier',
  preflightUnavailableBody: 'This build has no preflight command, so nothing below was measured here.',
  preflightBadgeUnmeasured: 'not measured',
  preflightScopeLine: 'Anchored prefix: tamper-evident, and only within the scope printed above.',
  preflightTailLine: 'Live tail: ',
  preflightTailClaim: 'tamper-evident only',

  /* ------------------------------------------------------------ ledger */
  ledgerTitle: 'Ledger status',
  ledgerSub: 'evm extra (opt-in) · operator-supplied RPC + contract addresses.',
  ledgerUnavailableTitle: 'No ledger is configured for this deployment',
  ledgerUnavailableBody: 'The evm extra is opt-in: this server has no RPC endpoint and no contract address, so nothing was queried.',
  ledgerAddrNone: 'no contract address configured',
  rpcTitle: 'RPC readers (≥ 2, finalized)',
  rpcNone: 'No RPC reader is configured.',
  rpcFoot: 'Two RPCs disagreeing → exit 2, never broken.',
  contractLiveness: 'AnchoringLiveness',
  contractLivenessDesc: 'Strictly increasing seq + writer signature.',
  contractRegistry: 'FingerprintRegistry',
  contractRegistryDesc: 'Append-only registry, fingerprint cross-check.',
  contractBonded: 'BondedCheckpoints',
  contractBondedDesc: 'Equivocation gets slashed (RFC 9162).',

  /* ---------------------------------------------------------- receipts */
  receiptsTitle: 'Receipt chain',
  receiptsSub:
    'A running hash over received checkpoints — the server cannot reorder confirmed history.',
  receiptsFoot: 'Mismatch at a seq → exit 1 · receipt_mismatch. Missing sidecar → not recorded.',
  receiptsNone: 'No receipts have been issued on this server yet.',
  colReceiptIndex: '#',
  colRunningHead: 'running head',
  receiptsVerifyTitle: 'receipts/verify',
  receiptsVerifyQuestion: 'Is the acknowledgment log internally consistent?',
  receiptsCrossTitle: 'receipts/cross-check',
  receiptsCrossQuestion: 'Does each entry still carry the hash acknowledged for it?',
  receiptsBrokenReceiptSeq: 'broken receipt seq {seq}',
  receiptsBrokenSeq: 'broken chain seq {seq}',

  /* ---------------------------------------------------------- read-api */
  readApi: 'Public read-API',
  readApiSub:
    'The endpoints a third party can read without asking this server for anything. Follow a link and the raw JSON opens in a new tab.',
  readApiPublicTitle: 'Public — no credential',
  readApiAuthedTitle: 'Bearer credential required (WAXSEAL_API_KEY)',
  readApiAuthedNote: 'Listed for completeness, not linked: a link that 401s teaches nothing.',
  readApiNeedsChain: 'Pick a chain to build the per-chain links:',
  readApiNoChain: 'This server holds no chain, so there is no per-chain URL to link to.',
  colMethod: 'method',
  colPath: 'path',
  colDesc: 'what it answers',
  epScope: 'the frozen scope statement every verdict is qualified by',
  epChains: 'the chain ids this server holds',
  epHead: 'current head (seq, entry_hash)',
  epEntries: 'read in write order, paginated',
  epReceipts: 'the per-append receipt records themselves',
  epReceiptsHead: 'the running receipt head',
  epReceiptsVerify: 'is the acknowledgment log internally consistent?',
  epReceiptsCross: 'does each entry still carry the hash acknowledged for it?',
  epWitness: 'checkpoints this server holds as a witness',
  epHealth: 'liveness only — no claim about any chain',
  epAppend: 'append · CAS on (seq, prev_hash) · 409 on loss',
  epVerify: 'run the verifier and return its verdict, argv and stdout',
  epReport: 'the full audit report as JSON',
  epSummary: 'entry count, byte size and head for one chain',
  epImports: 'imported trails held as read-only evidence',
  epWitnessPost: 'witness · WAXSEAL_WITNESS_API_KEY',

  /* ------------------------------------------------- users, roles, keys */
  usersTitle: 'Users & Roles',
  usersSub: 'The operators this server holds, the role each one has, and what a role grants.',
  operatorsTitle: 'Operators',
  colOperator: 'operator',
  colRole: 'role',
  colCreated: 'created',
  colStatus: 'status',
  operatorActive: 'active',
  operatorInactive: 'inactive',
  operatorInactiveWhy:
    'An inactive operator keeps its role and is granted no scope, so a deactivation cannot be undone by forgetting which role it had.',
  operatorNoEmail: 'no email address was recorded for this operator',
  operatorsNone:
    'This server holds no operators yet. `waxseal-server-admin seed` creates the first ones, and the form below adds another.',
  operatorsFoot: 'No 2FA and no last-active column: the server tracks neither.',
  rolesTitle: 'Roles',
  roleAdmin: 'Admin',
  roleAdminDesc: 'Manages the server, its operators and its keys — and still cannot edit an entry, because nobody can.',
  roleAuditor: 'Auditor',
  roleAuditorDesc:
    'Reads trails, runs verify / report / export-proof, imports evidence. Cannot append and cannot manage keys.',
  roleViewer: 'Viewer',
  roleViewerDesc: 'Read-only: the dashboard and the public read-API.',
  roleWriter: 'Writer',
  roleWriterDesc: 'Machine account. Appends and reads the head; cannot read the trail it writes to.',
  roleHolders: '{count} on this server',
  roleScopesFrom: 'Scopes as this server reports them for {username}.',
  roleScopesNone: 'No active operator holds this role, so the server reported no scope set for it.',

  /* ------------------------------------------------------------- invite */
  inviteTitle: 'Add an operator',
  inviteSub: 'A new operator holds a role and no key. Mint one for them on the API keys screen.',
  inviteUsername: 'username',
  inviteUsernameHint:
    'lowercase a–z, 0–9, dot, dash or underscore · 1–64 characters · starts alphanumeric',
  inviteDisplay: 'display name',
  inviteEmail: 'email (optional)',
  inviteRole: 'role',
  inviteSubmit: 'Create operator',
  inviteCreating: 'creating…',
  inviteCreated: 'Created {username} as {role}. No key has been minted for them yet.',
  inviteErrExists:
    'An operator named {username} already exists on this server. A username is the identity and is never reused, so this creates nothing.',
  inviteErrRole: 'The server rejected that role. Unknown roles are refused, never defaulted.',
  inviteErrUsername: 'The server rejected that username: {detail}',
  inviteErrOther: 'The server refused: {detail}',

  /* --------------------------------------------------------- api keys */
  keysTitle: 'API keys',
  keysSub: 'Bearer credentials for this server — minted once, stored as a SHA-256, never shown twice.',
  colKey: 'key',
  colFingerprint: 'fingerprint',
  colLastUsed: 'last used',
  keyOwner: 'owner {username}',
  keyNeverUsed: 'never used',
  keyNeverUsedWhy:
    'This key has not authenticated a request. That is a recorded fact about the key, not a date this screen failed to read.',
  keyActive: 'active',
  keyRevoked: 'revoked',
  keyRevokedAt: 'revoked {at}',
  keysNone: 'No API key has been minted on this server yet.',
  keysFoot: 'Revoked keys stay listed: a revocation is part of the history.',
  mintTitle: 'Mint a key',
  mintOperator: 'operator',
  mintLabel: 'label',
  mintLabelHint:
    'what this key is for — besides four characters of the secret, it is the only thing a listing can tell two keys apart by',
  mintSubmit: 'Mint key',
  mintMinting: 'minting…',
  mintNoOperators:
    'There is no operator to mint a key for. Create one on the Users & Roles screen first.',
  mintErrNoOperator: 'No operator named {username} exists on this server, so nothing was minted.',
  mintErrOther: 'The server refused: {detail}',
  mintedTitle: 'Copy this key now — it is shown once and never again',
  mintedBody: 'Only the SHA-256 was stored. Copy it now — it cannot be shown again.',
  mintedFor: '{label} · {username}',
  mintedCopy: 'Copy',
  mintedCopied: 'Copied',
  mintedDismiss: 'I have copied it — dismiss',
  revoke: 'Revoke',
  revoking: 'revoking…',
  revokeDone:
    'Revoked {label}. The key is refused from now on and its row stays listed as revoked.',
  revokeNothing: 'Nothing was revoked. {label} was already revoked, or no key here has that id.',
  revokeFailed: 'Revoke failed: {detail}',

  /* ------------------------------------------------ the credential in hand */
  principalTitle: 'This credential',
  principalOperator: 'Authenticated as {username}',
  principalKey: 'key {id}',
  principalScopes: 'What this credential grants, as the server reports it:',
  principalBootstrapTitle: 'The bootstrap key — a credential, not an operator',
  principalBootstrapBody: 'WAXSEAL_API_KEY from the server environment. Not an operator, and not a row below.',
  principalOpenTitle: 'This server has no credential configured',
  principalOpenBody: 'Every caller is admitted as “unauthenticated”. Minting the first API key closes this server.',
  principalSyntheticTitle: 'This credential is not one of the operators listed',
  principalSyntheticBody: 'whoami returned is_operator: false — a credential, not a person, and not a row below.',
  principalUnknown: 'The server has not said who this credential is.',
  patTitle: 'Personal access token',
  patBody: 'Either credential works: the bootstrap WAXSEAL_API_KEY, or an operator key. /v1/whoami says which you hold.',
  adminDocsWhere:
    'Seeding operators and minting the first key is documented in server/docs/deployment.md.',
  tokenTitle: 'Token for this browser tab',
  tokenSub:
    'Supplied here, held in sessionStorage, sent as a bearer header on /v1 reads. Never placed in a URL or an argv.',

  /* --------------------------------------------------------- benchmark */
  benchTitle: 'Benchmark',
  benchSub: 'Byte-counting measurements from receipt tests — no wall-clock.',
  benchPublishedTitle: 'Published figures, not a measurement of this deployment',
  benchPublishedBody: 'Figures from the 0.1.5 CHANGELOG reference workload. This server measured nothing.',
  benchFoot:
    'Falsifiability receipts: remove the optimization (deque / offset resume) → test goes red. Numbers land in the CHANGELOG.',
  benchTail: 'tail -n 5 on a 100k-entry trail (bytes read)',
  benchScan: 'cumulative integrity scan (re-reads)',
  benchReport: 'report / export-proof (trail read passes)',
  benchAppend: 'append (4000 entries)',
  benchDeltaOffsetResume: 'offset resume',
  benchDeltaUnchanged: 'unchanged (expected)',

  /* ------------------------------------------------------ integrations */
  intTitle: 'Integrations',
  intSub:
    '9 integrations — record before execution, redact before hashing, never block the host.',
  intDetectTitle: 'Installed state cannot be seen from here',
  intDetectBody: 'Not detected from here: a hook lives on the machine running the agent, which this server never reads.',
  provClaudeCode: 'PreToolUse / PostToolUse hooks',
  provCodex: 'lifecycle hooks · ≥ 0.149.0',
  provCursor: 'Agent Hooks (.cursor/hooks.json)',
  provLangchain: 'BaseCallbackHandler',
  provCrewai: 'event listener (crewai.events)',
  provOpenaiAgents: 'RunHooks',
  provHermes: 'plugin + gateway hook',
  provOpenclaw: 'audit-ledger exporter',
  provAgt: 'audit sink · new in 0.1.5',

  /* ------------------------------------------------------- threat tiers */
  tier1: 'Tier 1',
  tier1Attack: 'Edit / delete / reorder entries on disk',
  tier1Defense: 'hash chain → exit 1',
  tier2: 'Tier 2',
  tier2Attack: 'Rewrite the whole suffix',
  tier2Defense: 'forward-secure seals',
  tier3: 'Tier 3',
  tier3Attack: 'Rewrite with a leaked keyfile',
  tier3Defense: 'keyed FssAgg aggregate',
  tier4: 'Tier 4',
  tier4Attack: 'Rewrite .anchors on the same disk',
  tier4Defense: 'external anchors: TSA + witness',
  tier5: 'Tier 5',
  tier5Attack: 'Colluding server · split-view',
  tier5Defense: 'needs separate pin + off-domain witness',
  tier6: 'Tier 6',
  tier6Attack: 'Every domain + history wipe',
  tier6Defense: 'needs finalized ledger or WORM',

  /* --------------------------------------------------------- not found */
  notFoundTitle: 'No such screen',
  notFoundBody: 'This URL does not name a screen in this console.',

  /* ------------------------------------------------- state explanations */
  stateOkExplain: 'chain intact',
  stateBrokenExplain: 'a break was found',
  stateUnverifiableExplain: 'unverifiable by name — this is NOT evidence of tampering',
  stateAbsentExplain: 'nothing was read: no trail at that path',
  stateUnavailableExplain: 'this waxseal build has no such command (planned, not shipped)',
  stateUsageErrorExplain:
    'the command was invoked wrongly — argparse rejected it, so no verdict was computed',
  stateUnexpectedExitExplain:
    'the command exited with a code this server does not map to a verdict — no verdict was computed',
  stateUnknownExplain: 'this server returned a status this build does not recognise',
  stateUnverifiableDetail: 'Some rows carry a fingerprint this build cannot reproduce — a fact about this verifier, not about the rows.',
  stateAbsentDetail: 'No trail at the path derived for this chain. Nothing read, nothing created.',
  stateUnavailableDetail: 'This build does not offer that subcommand. Shown, not hidden, so “not shipped” is never read as “found nothing”.',
} as const

export type MessageKey = keyof typeof en

const vi: Record<MessageKey, string> = {
  /* ------------------------------------------------------------- chrome */
  sectionPortal: 'Portal',
  sectionAdmin: 'Quản trị',
  sidebarServer: 'Server {version}',
  sidebarServerUnknown: 'Server · chưa rõ phiên bản',
  headPill: 'head {hash}',
  headPillNoChain: 'head · chưa chọn chain',
  headPillEmpty: 'head · chain rỗng',
  readOnly: 'chỉ đọc',
  readOnlyTitle:
    'Console này không bao giờ ghi thêm, sửa, đảo hay “vá” một entry — không credential nào nó cầm được cấp quyền đó, vì scope đó không tồn tại. Nó có ghi ba thứ không phải chain: một trail được import, lưu như bằng chứng chỉ đọc; một bản ghi operator; và một API key.',
  langVi: 'VI',
  langEn: 'EN',
  motto: 'Verify chỉ báo cáo — không sửa, không xóa.',
  skipToContent: 'Tới nội dung chính',
  ledgerNoChain: 'Server chưa có chain nào để kiểm tra on-chain.',
  ledgerNotConfigured: 'Chưa cấu hình ledger',
  ledgerMissing: 'Đặt {keys} trong Cài đặt để truy vấn.',
  ledgerQueried: 'đã truy vấn',
  ledgerQueriedWhy: 'Đọc từ các RPC endpoint đã cấu hình, không phải suy đoán.',
  navSettings: 'Cài đặt',
  setTitle: 'Cài đặt',
  setSub: 'Credential, biến môi trường, và các tham số bạn sửa được.',
  setStoredTitle: 'Cấu hình server',
  setEnvTitle: 'Triển khai',
  setEnvWhy: 'Đặt trong biến môi trường của process. Muốn đổi thì phải khởi động lại server.',
  setReadOnly: 'chỉ đọc',
  setStored: 'đã lưu',
  setDefault: 'mặc định',
  setUnset: 'chưa cấu hình',
  setSave: 'Lưu',
  setReset: 'Đặt lại',
  setIsSet: 'đã đặt',
  setIsUnset: 'chưa đặt',
  setSecretWhy: 'Là credential. Server chỉ báo đã đặt hay chưa, không bao giờ báo giá trị.',
  setBackendMemory: 'trong bộ nhớ',
  setBackendMemoryWhy: 'Chưa cấu hình database, nên các cài đặt này mất khi khởi động lại.',
  setBackendPg: 'PostgreSQL',
  setBackendPgWhy: 'Lưu trong database và giữ qua các lần khởi động lại.',
  authNeededTitle: 'Lệnh đọc này cần credential',
  authNeededBody: 'API token được đặt một lần, trong Cài đặt.',
  authNeededLink: 'Tới Cài đặt',
  run: 'Chạy',
  running: 'Đang chạy…',
  runTail: 'Tail',
  runCheckpoint: 'Checkpoint',

  navCons: 'Nhất quán',
  navHandoff: 'Chuyển giao',
  navTickets: 'Vé',
  navCadence: 'Nhịp anchor',

  consTitle: 'Nhất quán',
  consSub: 'Checkpoint bạn đang giữ còn nằm trên chain này không?',
  consChain: 'Chain',
  consOldSeq: 'Seq cũ',
  consOldRoot: 'Root cũ',
  consRootShape: '64 ký tự hex',
  consNoChains: 'Server chưa có chain nào.',

  handoffTitle: 'Chuyển giao',
  handoffSub: 'Đối chiếu binding của trail ủy quyền với lịch sử trail gốc.',
  handoffDelegate: 'Trail ủy quyền',
  handoffOrigin: 'Trail gốc',
  handoffNoChains: 'Server chưa có chain nào.',

  ticketsTitle: 'Vé',
  ticketsSub: 'Đối chiếu vé đã phát hành với trail.',
  ticketsChain: 'Chain',
  ticketsIssuer: 'Nơi phát hành',
  ticketsLease: 'Cỡ lease',
  ticketsIssued: 'Khoảng đã phát',
  ticketsNoChains: 'Server chưa có chain nào.',
  ticketsUnmeasured: 'Chưa đo — không có dữ liệu phát hành',
  ticketsNoDrops: 'Không phát hiện mất vé',
  ticketsDropped: 'Thiếu {n} vé',
  ticketsBlindSpot: 'Giới hạn điểm mù {bound}, lease {lease}.',

  cadTitle: 'Nhịp anchor',
  cadSub: 'Khoảng anchor tối ưu chi phí, tính từ số đo của bạn.',
  cadLam: 'Tốc độ λ',
  cadC: 'Chi phí anchor',
  cadW: 'Thiệt hại mỗi entry',
  cadRho: 'Chiết khấu ρ',
  cadDelta: 'Trễ anchor',
  cadTMax: 'Trễ tối đa',
  cadM: 'Hệ số',
  navOpen: 'Mở menu',
  navClose: 'Đóng menu',

  /* --------------------------------------------------------------- nav */
  navDash: 'Dashboard',
  navImport: 'Import',
  navPreflight: 'Preflight',
  navLedger: 'Ledger',
  navReceipts: 'Receipts',
  navApi: 'Read-API',
  navUsers: 'Users & Roles',
  navKeys: 'API keys',
  navBench: 'Benchmark',
  navInt: 'Integrations',
  navTrail: 'Trail',
  navNotFound: 'Không tìm thấy',

  /* ------------------------------------------------------ shared states */
  loading: 'đang đọc…',
  loadFailed: 'Yêu cầu thất bại: {detail}',
  retry: 'Thử lại',
  notMeasured: 'chưa đo',
  notRecorded: 'không ghi nhận',
  notConfigured: 'chưa cấu hình',
  notDetected: 'không phát hiện được từ đây',
  notApplicable: '—',
  unavailableHere: 'bản build này không có',
  serverSilent: 'server không trả lời điều này',
  nothingYet: 'chưa có gì',
  noChains: 'Server này chưa có chain nào. Ghi một entry và nó sẽ xuất hiện ở đây.',
  authNeeded: 'Server này cần bearer credential cho các lệnh đọc /v1.',
  authOpen: 'Không cần credential: chưa cấp khóa nào, WAXSEAL_API_KEY chưa đặt. Cấp khóa đầu tiên là đóng lại.',
  authUnknown: 'Server chưa cho biết các lệnh đọc /v1 có cần credential hay không.',
  authField: 'WAXSEAL_API_KEY',
  authApply: 'Dùng token này',
  authClear: 'Quên token',
  authHint:
    'Chỉ giữ trong tab trình duyệt này. Token gửi kèm request /v1; read-API công khai không nhận credential.',

  notMeasuredWhy: '“chưa đo” không phải là 0. Không có phép đo nào được thực hiện nên không báo cáo con số nào.',
  unverifiableWhy: 'unverifiable ≠ tampered',

  /* --------------------------------------------------------- dashboard */
  statChains: 'Chains',
  statChainsSub: '{count} trên server này',
  statVerdict: 'Verdict',
  statDropsTitle: 'Dropped writes',
  statDrops: 'tối thiểu đã đo (.drops)',
  statDropsPartial: 'đo được trên {measured}/{total} chain',
  statDropsNone: 'không chain nào báo cáo một phép đo',
  statAnchor: 'Anchor gần nhất',
  statAnchorChecked: 'đã kiểm {checked} checkpoint đã anchor',
  statAnchorNone: 'không chain nào có sidecar .anchors',
  trailsTitle: 'Trail theo dự án',
  colChain: 'chain',
  colSegments: 'segments',
  colEntries: 'entries',
  colSize: 'size',
  colVerdict: 'verdict',
  colAnchor: 'anchor cuối',
  segmentsNotCountedTitle: 'Chưa đo số segment cho dòng này. Mở tab Segments của trail để chạy phép kiểm tra.',
  chainEntriesUnknown: 'không lấy được số entry: {detail}',
  chainEmpty: 'chain rỗng — chưa ghi entry nào',
  chainHead: 'head seq {seq}',

  /* ------------------------------------------------------------- trail */
  backToDashboard: '← Dashboard',
  runVerify: 'Verify',
  runReport: 'Report',
  runProof: 'Export proof',
  runProofEmptyTitle: 'Không có entry nào để chứng minh: chain rỗng.',
  tabEntries: 'Entries',
  tabSegments: 'Segments',
  tabSidecars: 'Sidecars',
  tabOutput: 'Output',
  colTs: 'ts',
  colPayloadType: 'payload_type',
  colPayload: 'payload (đã redact)',
  colEntryHash: 'entry_hash',
  entriesFoot: 'Payload đã redact trước khi hash.',
  entriesFootWhy: 'Redaction chạy trước khi tính payload_hash, nên bản rõ chưa từng tới server này.',
  entriesEmpty: 'Chain này chưa có entry nào.',
  entriesMore: 'Đang hiển thị {shown} entry đầu. Chain còn nhiều hơn.',
  segFoot: 'Xoay vòng ở 16 MiB · segment nối nhau bằng rotation binding seq-0.',
  segmentsUnavailableTitle: 'Bản build này không kiểm tra được sealed segment',
  verifyFoot: 'Kết quả + exit code từ CLI waxseal, trình nguyên văn.',
  argvLabel: 'argv',
  exitLabel: 'exit {code}',
  exitNone: 'không có exit code: lệnh chưa từng chạy',
  scopeLabel: 'Phạm vi',

  /* ---------------------------------------------------------- sidecars */
  sidecarAttest: '.attest',
  sidecarAttestDesc: 'Forward-secure seal + FssAgg accumulator',
  sidecarAnchors: '.anchors',
  sidecarAnchorsDesc: 'Checkpoint đã anchor · TSA + witness',
  sidecarDrops: '.drops',
  sidecarDropsDesc: 'Dropped writes — tối thiểu đã đo',
  sidecarPin: '.pin',
  sidecarPinDesc: 'Trạng thái pin phía verifier (SPEC §13)',
  sidecarReceiptsVerify: '.receipts · verify',
  sidecarReceiptsVerifyDesc:
    'Log biên nhận có nhất quán với chính nó không? Câu hỏi chỉ về riêng cái log.',
  sidecarReceiptsCross: '.receipts · cross-check',
  sidecarReceiptsCrossDesc:
    'Entry tại seq đó còn mang đúng hash đã được xác nhận không? Bắt được kiểu viết lại cục bộ tự nhất quán.',
  sidecarSealkey: '.sealkey',
  sidecarSealkeyDesc: 'Epoch key một chiều · A₀ escrow ngoài máy',
  sidecarSealkeyStatus: 'không có endpoint nào của server đọc sidecar này',
  sidecarChecked: 'đã kiểm {count}',
  sidecarCheckedNone: 'chưa kiểm gì',

  /* ------------------------------------------------------------ import */
  importTitle: 'Import trail',
  importSub: 'Trail nhập là bằng chứng — lưu read-only, không ghi tiếp.',
  dropTitle: 'Thả trail.jsonl / trail.db vào đây',
  dropSub: 'kèm sidecar .attest · .anchors · .drops · .receipts nếu có',
  chooseFile: 'Chọn tệp',
  imported: 'Đã nhập',
  importUploading: 'đang tải {name}…',
  importFailed: 'Tải lên thất bại: {detail}',
  importNone: 'Chưa nhập trail nào.',
  colImportSource: 'nguồn',
  colImportReason: 'lý do',
  importSourceUpload: 'tải lên {at} · {size}',

  /* --------------------------------------------------------- preflight */
  preflightTitle: 'Preflight',
  preflightSub: 'Cấu hình hiện tại chống được bậc nào trong thang năng lực kẻ tấn công.',
  preflightUnavailableTitle: 'Bản build này chưa xác định được bậc của một triển khai',
  preflightUnavailableBody: 'Bản build này không có lệnh preflight, nên chưa đo gì bên dưới.',
  preflightBadgeUnmeasured: 'chưa đo',
  preflightScopeLine: 'Tiền tố đã anchor: tamper-evident, và chỉ trong phạm vi in ở trên.',
  preflightTailLine: 'Đuôi đang ghi: ',
  preflightTailClaim: 'tamper-evident only',

  /* ------------------------------------------------------------ ledger */
  ledgerTitle: 'Ledger status',
  ledgerSub: 'Extra evm (opt-in) · RPC + địa chỉ contract do operator cung cấp.',
  ledgerUnavailableTitle: 'Triển khai này chưa cấu hình ledger nào',
  ledgerUnavailableBody: 'Extra evm là opt-in: server này không có RPC endpoint lẫn địa chỉ contract, nên chưa truy vấn gì.',
  ledgerAddrNone: 'chưa cấu hình địa chỉ contract',
  rpcTitle: 'RPC readers (≥ 2, finalized)',
  rpcNone: 'Chưa cấu hình RPC reader nào.',
  rpcFoot: 'Hai RPC bất đồng → exit 2, không bao giờ broken.',
  contractLiveness: 'AnchoringLiveness',
  contractLivenessDesc: 'Seq tăng nghiêm ngặt + chữ ký writer.',
  contractRegistry: 'FingerprintRegistry',
  contractRegistryDesc: 'Registry append-only, cross-check fingerprint.',
  contractBonded: 'BondedCheckpoints',
  contractBondedDesc: 'Equivocation bị slash (RFC 9162).',

  /* ---------------------------------------------------------- receipts */
  receiptsTitle: 'Receipt chain',
  receiptsSub:
    'Running hash trên các checkpoint đã nhận — server không sắp lại được lịch sử đã xác nhận.',
  receiptsFoot: 'Mismatch tại một seq → exit 1 · receipt_mismatch. Sidecar vắng → not recorded.',
  receiptsNone: 'Server này chưa phát hành biên nhận nào.',
  colReceiptIndex: '#',
  colRunningHead: 'running head',
  receiptsVerifyTitle: 'receipts/verify',
  receiptsVerifyQuestion: 'Log biên nhận có nhất quán với chính nó không?',
  receiptsCrossTitle: 'receipts/cross-check',
  receiptsCrossQuestion: 'Mỗi entry còn mang đúng hash đã được xác nhận cho nó không?',
  receiptsBrokenReceiptSeq: 'receipt seq hỏng: {seq}',
  receiptsBrokenSeq: 'chain seq hỏng: {seq}',

  /* ---------------------------------------------------------- read-api */
  readApi: 'Read-API công khai',
  readApiSub:
    'Những endpoint mà bên thứ ba đọc được mà không cần xin phép server này. Bấm vào link, JSON thô mở ở tab mới.',
  readApiPublicTitle: 'Công khai — không cần credential',
  readApiAuthedTitle: 'Cần bearer credential (WAXSEAL_API_KEY)',
  readApiAuthedNote: 'Liệt kê cho đủ, không đặt link: link trả 401 chẳng dạy được gì.',
  readApiNeedsChain: 'Chọn một chain để dựng các link theo chain:',
  readApiNoChain: 'Server này chưa có chain nào nên chưa có URL theo chain để liên kết.',
  colMethod: 'method',
  colPath: 'path',
  colDesc: 'trả lời điều gì',
  epScope: 'câu tuyên bố phạm vi đã đóng băng, dùng để giới hạn mọi verdict',
  epChains: 'các chain id server này đang giữ',
  epHead: 'head hiện tại (seq, entry_hash)',
  epEntries: 'đọc theo thứ tự ghi, phân trang',
  epReceipts: 'chính các bản ghi biên nhận per-append',
  epReceiptsHead: 'running receipt head',
  epReceiptsVerify: 'log biên nhận có nhất quán với chính nó không?',
  epReceiptsCross: 'mỗi entry còn mang đúng hash đã xác nhận không?',
  epWitness: 'các checkpoint server này giữ với vai trò witness',
  epHealth: 'chỉ báo sống — không khẳng định gì về chain nào',
  epAppend: 'append · CAS trên (seq, prev_hash) · 409 khi thua',
  epVerify: 'chạy verifier và trả verdict, argv, stdout',
  epReport: 'toàn bộ audit report dạng JSON',
  epSummary: 'số entry, dung lượng byte và head của một chain',
  epImports: 'các trail đã nhập, giữ như bằng chứng chỉ đọc',
  epWitnessPost: 'witness · WAXSEAL_WITNESS_API_KEY',

  /* ------------------------------------------------- users, roles, keys */
  usersTitle: 'Users & Roles',
  usersSub: 'Các operator server này đang giữ, vai trò của từng người, và một vai trò cho phép những gì.',
  operatorsTitle: 'Operator',
  colOperator: 'operator',
  colRole: 'vai trò',
  colCreated: 'tạo lúc',
  colStatus: 'trạng thái',
  operatorActive: 'đang hoạt động',
  operatorInactive: 'đã vô hiệu',
  operatorInactiveWhy:
    'Operator bị vô hiệu vẫn giữ vai trò của mình nhưng không được cấp scope nào, nên không thể vô tình khôi phục quyền bằng cách quên mất họ từng ở vai trò gì.',
  operatorNoEmail: 'không ghi nhận địa chỉ email nào cho operator này',
  operatorsNone:
    'Server này chưa có operator nào. `waxseal-server-admin seed` tạo những người đầu tiên, và biểu mẫu bên dưới thêm người tiếp theo.',
  operatorsFoot: 'Không có cột 2FA và “hoạt động lần cuối”: server không theo dõi cả hai.',
  rolesTitle: 'Vai trò',
  roleAdmin: 'Admin',
  roleAdminDesc: 'Quản trị server, operator và khóa — và vẫn không sửa được entry, vì không ai sửa được.',
  roleAuditor: 'Auditor',
  roleAuditorDesc:
    'Đọc trail, chạy verify / report / export-proof, import bằng chứng. Không append được và không quản lý được khóa.',
  roleViewer: 'Viewer',
  roleViewerDesc: 'Chỉ đọc: dashboard và read-API công khai.',
  roleWriter: 'Writer',
  roleWriterDesc: 'Tài khoản máy. Append và đọc head; không đọc được trail nó ghi vào.',
  roleHolders: '{count} người trên server này',
  roleScopesFrom: 'Scope đúng như server báo cáo cho {username}.',
  roleScopesNone: 'Không operator hoạt động nào giữ vai trò này, nên server chưa báo tập scope cho nó.',

  /* ------------------------------------------------------------- invite */
  inviteTitle: 'Thêm operator',
  inviteSub: 'Operator mới có vai trò nhưng chưa có khóa. Cấp khóa cho họ ở màn hình API keys.',
  inviteUsername: 'username',
  inviteUsernameHint:
    'chữ thường a–z, 0–9, dấu chấm, gạch ngang hoặc gạch dưới · 1–64 ký tự · bắt đầu bằng chữ hoặc số',
  inviteDisplay: 'tên hiển thị',
  inviteEmail: 'email (tùy chọn)',
  inviteRole: 'vai trò',
  inviteSubmit: 'Tạo operator',
  inviteCreating: 'đang tạo…',
  inviteCreated: 'Đã tạo {username} với vai trò {role}. Chưa cấp khóa nào cho họ.',
  inviteErrExists:
    'Server này đã có operator tên {username}. Username là danh tính và không bao giờ dùng lại, nên lần này không tạo ra gì cả.',
  inviteErrRole: 'Server từ chối vai trò đó. Vai trò lạ bị từ chối, không bao giờ lấy mặc định.',
  inviteErrUsername: 'Server từ chối username đó: {detail}',
  inviteErrOther: 'Server từ chối: {detail}',

  /* --------------------------------------------------------- api keys */
  keysTitle: 'API keys',
  keysSub: 'Bearer credential của server này — cấp một lần, lưu dưới dạng SHA-256, không bao giờ hiện lại lần hai.',
  colKey: 'khóa',
  colFingerprint: 'fingerprint',
  colLastUsed: 'dùng lần cuối',
  keyOwner: 'chủ sở hữu {username}',
  keyNeverUsed: 'chưa từng dùng',
  keyNeverUsedWhy:
    'Khóa này chưa xác thực request nào. Đó là một dữ kiện đã ghi nhận về khóa, không phải một ngày mà màn hình này đọc không ra.',
  keyActive: 'đang hiệu lực',
  keyRevoked: 'đã thu hồi',
  keyRevokedAt: 'thu hồi {at}',
  keysNone: 'Server này chưa cấp API key nào.',
  keysFoot: 'Khóa đã thu hồi vẫn được liệt kê: một lần thu hồi là phần của lịch sử.',
  mintTitle: 'Cấp khóa',
  mintOperator: 'operator',
  mintLabel: 'nhãn',
  mintLabelHint:
    'khóa này dùng để làm gì — ngoài bốn ký tự đầu của phần bí mật, đây là thứ duy nhất giúp phân biệt hai khóa trong danh sách',
  mintSubmit: 'Cấp khóa',
  mintMinting: 'đang cấp…',
  mintNoOperators:
    'Chưa có operator nào để cấp khóa. Hãy tạo một người ở màn hình Users & Roles trước.',
  mintErrNoOperator: 'Server này không có operator tên {username}, nên không cấp khóa nào.',
  mintErrOther: 'Server từ chối: {detail}',
  mintedTitle: 'Sao chép khóa này ngay — nó chỉ hiện một lần và không bao giờ hiện lại',
  mintedBody: 'Server chỉ lưu SHA-256. Hãy copy ngay — không thể hiện lại.',
  mintedFor: '{label} · {username}',
  mintedCopy: 'Sao chép',
  mintedCopied: 'Đã chép',
  mintedDismiss: 'Tôi đã chép xong — đóng lại',
  revoke: 'Thu hồi',
  revoking: 'đang thu hồi…',
  revokeDone:
    'Đã thu hồi {label}. Từ giờ khóa bị từ chối, và dòng của nó vẫn nằm lại trong danh sách với trạng thái đã thu hồi.',
  revokeNothing: 'Không thu hồi gì. {label} đã bị thu hồi trước đó, hoặc không có khóa nào mang id đó.',
  revokeFailed: 'Thu hồi thất bại: {detail}',

  /* ------------------------------------------------ the credential in hand */
  principalTitle: 'Credential đang dùng',
  principalOperator: 'Đang xác thực với tư cách {username}',
  principalKey: 'khóa {id}',
  principalScopes: 'Credential này cho phép những gì, đúng như server báo cáo:',
  principalBootstrapTitle: 'Khóa bootstrap — một credential, không phải một operator',
  principalBootstrapBody: 'WAXSEAL_API_KEY từ môi trường server. Không phải operator, không có dòng bên dưới.',
  principalOpenTitle: 'Server này chưa cấu hình credential nào',
  principalOpenBody: 'Mọi lời gọi được nhận là “unauthenticated”. Cấp API key đầu tiên sẽ đóng server này.',
  principalSyntheticTitle: 'Credential này không phải một trong các operator được liệt kê',
  principalSyntheticBody: 'whoami trả về is_operator: false — một credential, không phải người, không có dòng bên dưới.',
  principalUnknown: 'Server chưa cho biết credential này là ai.',
  patTitle: 'Personal access token',
  patBody: 'Dùng được cả hai: WAXSEAL_API_KEY bootstrap, hoặc khóa operator. /v1/whoami cho biết bạn đang cầm cái nào.',
  adminDocsWhere:
    'Cách seed operator và cấp khóa đầu tiên được ghi trong server/docs/deployment.md.',
  tokenTitle: 'Token cho tab trình duyệt này',
  tokenSub:
    'Nhập ở đây, giữ trong sessionStorage, gửi kèm header bearer cho các lệnh đọc /v1. Không bao giờ nằm trong URL hay argv.',

  /* --------------------------------------------------------- benchmark */
  benchTitle: 'Benchmark',
  benchSub: 'Số đo byte-counting từ test receipts — không wall-clock.',
  benchPublishedTitle: 'Số đã công bố, không phải phép đo trên triển khai này',
  benchPublishedBody: 'Số liệu từ workload tham chiếu trong CHANGELOG 0.1.5. Server này chưa đo gì.',
  benchFoot:
    'Biên nhận khả phủ chứng: bỏ tối ưu (deque / offset resume) → test đỏ. Số đo ghi vào CHANGELOG.',
  benchTail: 'tail -n 5 trên trail 100k entry (bytes đọc)',
  benchScan: 'integrity scan tích lũy (đọc lại)',
  benchReport: 'report / export-proof (lượt đọc trail)',
  benchAppend: 'append (4000 entries)',
  benchDeltaOffsetResume: 'resume theo offset',
  benchDeltaUnchanged: 'không đổi (đúng kỳ vọng)',

  /* ------------------------------------------------------ integrations */
  intTitle: 'Integrations',
  intSub: '9 tích hợp — ghi trước khi thực thi, redact trước khi hash, không bao giờ chặn host.',
  intDetectTitle: 'Không nhìn thấy trạng thái cài đặt từ đây',
  intDetectBody: 'Không phát hiện được từ đây: hook nằm trên máy chạy agent, server này không đọc tới đó.',
  provClaudeCode: 'PreToolUse / PostToolUse hooks',
  provCodex: 'lifecycle hooks · ≥ 0.149.0',
  provCursor: 'Agent Hooks (.cursor/hooks.json)',
  provLangchain: 'BaseCallbackHandler',
  provCrewai: 'event listener (crewai.events)',
  provOpenaiAgents: 'RunHooks',
  provHermes: 'plugin + gateway hook',
  provOpenclaw: 'audit-ledger exporter',
  provAgt: 'audit sink · mới trong 0.1.5',

  /* ------------------------------------------------------- threat tiers */
  tier1: 'Bậc 1',
  tier1Attack: 'Sửa / xóa / đảo entry trên đĩa',
  tier1Defense: 'hash chain → exit 1',
  tier2: 'Bậc 2',
  tier2Attack: 'Rewrite toàn suffix',
  tier2Defense: 'forward-secure seal',
  tier3: 'Bậc 3',
  tier3Attack: 'Rewrite khi keyfile lộ',
  tier3Defense: 'FssAgg keyed aggregate',
  tier4: 'Bậc 4',
  tier4Attack: 'Rewrite cả .anchors cùng đĩa',
  tier4Defense: 'anchor ngoài: TSA + witness',
  tier5: 'Bậc 5',
  tier5Attack: 'Server thông đồng · split-view',
  tier5Defense: 'cần pin tách đĩa + witness khác miền',
  tier6: 'Bậc 6',
  tier6Attack: 'Giữ mọi miền + xóa lịch sử',
  tier6Defense: 'cần ledger finalized hoặc WORM',

  /* --------------------------------------------------------- not found */
  notFoundTitle: 'Không có màn hình này',
  notFoundBody: 'URL này không trỏ tới màn hình nào trong console.',

  /* ------------------------------------------------- state explanations */
  stateOkExplain: 'chain nguyên vẹn',
  stateBrokenExplain: 'đã tìm thấy một chỗ đứt',
  stateUnverifiableExplain: 'unverifiable by name — đây KHÔNG phải bằng chứng bị sửa',
  stateAbsentExplain: 'không đọc được gì: không có trail ở đường dẫn đó',
  stateUnavailableExplain: 'bản waxseal này không có lệnh đó (đã lên kế hoạch, chưa ship)',
  stateUsageErrorExplain:
    'lệnh bị gọi sai — argparse từ chối, nên không có verdict nào được tính',
  stateUnexpectedExitExplain:
    'lệnh thoát với mã mà server này không ánh xạ thành verdict — không có verdict nào được tính',
  stateUnknownExplain: 'server trả về một status mà bản build này không nhận ra',
  stateUnverifiableDetail: 'Một số row mang fingerprint bản build này không tái tạo được — đây là điều về verifier, không phải về row.',
  stateAbsentDetail: 'Không có trail ở đường dẫn suy ra cho chain này. Không đọc gì, không tạo gì.',
  stateUnavailableDetail: 'Bản build này không có subcommand đó. Vẫn hiện thay vì ẩn, để “chưa ship” không bị đọc thành “không tìm thấy gì”.',
}

const TABLES: Record<Lang, Record<MessageKey, string>> = { en, vi }

function isLang(value: string | null): value is Lang {
  return value === 'vi' || value === 'en'
}

function load(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return isLang(stored) ? stored : DEFAULT_LANG
  } catch {
    return DEFAULT_LANG
  }
}

export const lang = ref<Lang>(load())

export function setLang(next: Lang): void {
  lang.value = next
  try {
    localStorage.setItem(STORAGE_KEY, next)
  } catch {
    /* Storage can be denied outright; the in-memory choice still holds. */
  }
  document.documentElement.lang = next
}

export type MessageVars = Record<string, string | number>

const PLACEHOLDER = /\{(\w+)\}/g

/** A key with no string is never rendered blank: a blank label is invisible in
 * review and ships. In development it renders as `⟦key⟧` and warns. */
function resolve(table: Record<MessageKey, string>, key: MessageKey): string {
  const value = table[key]
  if (typeof value === 'string' && value.length > 0) return value
  if (import.meta.env.DEV) {
    console.warn(`[i18n] missing message for key "${String(key)}"`)
  }
  return `⟦${String(key)}⟧`
}

export function translate(target: Lang, key: MessageKey, vars?: MessageVars): string {
  const text = resolve(TABLES[target], key)
  if (!vars) return text
  return text.replace(PLACEHOLDER, (whole, name: string) =>
    name in vars ? String(vars[name]) : whole,
  )
}

export interface I18n {
  lang: typeof lang
  t: (key: MessageKey, vars?: MessageVars) => string
  setLang: (next: Lang) => void
}

/** The reactive accessor every component uses. `t` reads `lang.value`, so a
 * toggle re-renders every string on the page without a reload. */
export function useI18n(): I18n {
  return {
    lang,
    t: (key: MessageKey, vars?: MessageVars) => translate(lang.value, key, vars),
    setLang,
  }
}

/** For the handful of places that need a computed rather than a call, such as
 * a `document.title` watcher. */
export function message(key: MessageKey, vars?: MessageVars): ComputedRef<string> {
  return computed(() => translate(lang.value, key, vars))
}
