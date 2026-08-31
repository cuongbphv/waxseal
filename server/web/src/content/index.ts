/* Editorial content: facts about the library and the threat model that no
 * endpoint can report, held as data rather than markup.
 *
 * Everything here is a real published fact — the six attacker tiers are the
 * threat model's, the nine integrations are the ones the library ships, the
 * four benchmark figures are the ones in the 0.1.5 CHANGELOG, the three
 * contracts are the designed Workstream F surface. None of it is a measurement
 * of THIS deployment, and every screen that renders it says so.
 *
 * Proper nouns ("Claude Code"), shell commands (`waxseal install codex`) and
 * type names ("AnchoringLiveness") are literals rather than message keys: they
 * are identical in both languages, and translating an install command would
 * make it wrong.
 */

import type { RoleName } from '@/lib/api'
import type { MessageKey } from '@/lib/i18n'

/* ---------------------------------------------------------- threat tiers */

export interface Tier {
  numberKey: MessageKey
  attackKey: MessageKey
  defenseKey: MessageKey
}

export const TIERS: readonly Tier[] = [
  { numberKey: 'tier1', attackKey: 'tier1Attack', defenseKey: 'tier1Defense' },
  { numberKey: 'tier2', attackKey: 'tier2Attack', defenseKey: 'tier2Defense' },
  { numberKey: 'tier3', attackKey: 'tier3Attack', defenseKey: 'tier3Defense' },
  { numberKey: 'tier4', attackKey: 'tier4Attack', defenseKey: 'tier4Defense' },
  { numberKey: 'tier5', attackKey: 'tier5Attack', defenseKey: 'tier5Defense' },
  { numberKey: 'tier6', attackKey: 'tier6Attack', defenseKey: 'tier6Defense' },
]

/* ---------------------------------------------------------- integrations */

export interface Provider {
  name: string
  /** Two-letter mark for the design's rounded tile. */
  mono: string
  mechanismKey: MessageKey
  /** The command or the word `import`, verbatim — never translated. */
  install: string
}

export const PROVIDERS: readonly Provider[] = [
  { name: 'Claude Code', mono: 'CC', mechanismKey: 'provClaudeCode', install: 'waxseal install claude-code' },
  { name: 'Codex CLI', mono: 'CX', mechanismKey: 'provCodex', install: 'waxseal install codex' },
  { name: 'Cursor', mono: 'CU', mechanismKey: 'provCursor', install: 'waxseal install cursor' },
  { name: 'LangChain', mono: 'LC', mechanismKey: 'provLangchain', install: 'import · library' },
  { name: 'CrewAI', mono: 'CR', mechanismKey: 'provCrewai', install: 'import · library' },
  { name: 'OpenAI Agents', mono: 'OA', mechanismKey: 'provOpenaiAgents', install: 'import · library' },
  { name: 'hermes-agent', mono: 'HM', mechanismKey: 'provHermes', install: 'waxseal install hermes' },
  { name: 'OpenClaw', mono: 'OC', mechanismKey: 'provOpenclaw', install: 'waxseal install openclaw' },
  { name: 'Microsoft AGT', mono: 'GT', mechanismKey: 'provAgt', install: 'waxseal install agt' },
]

/* -------------------------------------------------------------- contracts */

export interface LedgerContract {
  nameKey: MessageKey
  descriptionKey: MessageKey
}

export const LEDGER_CONTRACTS: readonly LedgerContract[] = [
  { nameKey: 'contractLiveness', descriptionKey: 'contractLivenessDesc' },
  { nameKey: 'contractRegistry', descriptionKey: 'contractRegistryDesc' },
  { nameKey: 'contractBonded', descriptionKey: 'contractBondedDesc' },
]

/* ------------------------------------------------------------------ roles */

/** The four roles the server defines, with the prose that explains each.
 *
 * There are no scope lists here on purpose. The role → scope table is fixed
 * server-side and each operator reports its own `scopes`; a second copy in this
 * file would be a permission model that drifts from the one actually enforced.
 * This module carries only what no endpoint reports — the sentence a role means
 * — and the `id` that joins it to the server's own data.
 *
 * The Admin line is the doctrine itself: an admin manages the server, its
 * operators and its keys, and STILL cannot edit an entry, because nobody can.
 * That is not a policy this build chose to apply. There is no `entries:edit`
 * scope in the server's vocabulary to grant, so no key it can mint carries one.
 */
export interface Role {
  /** The server's own role token, and the join with an operator's `role`. */
  id: RoleName
  nameKey: MessageKey
  descriptionKey: MessageKey
}

export const ROLES: readonly Role[] = [
  { id: 'admin', nameKey: 'roleAdmin', descriptionKey: 'roleAdminDesc' },
  { id: 'auditor', nameKey: 'roleAuditor', descriptionKey: 'roleAuditorDesc' },
  { id: 'writer', nameKey: 'roleWriter', descriptionKey: 'roleWriterDesc' },
  { id: 'viewer', nameKey: 'roleViewer', descriptionKey: 'roleViewerDesc' },
]

/* -------------------------------------------------------------- benchmark */

/** A published figure from the 0.1.5 CHANGELOG, with the bar widths the design
 * draws. `deltaKey` is set where the delta is prose rather than a percentage —
 * a percentage would be translated to itself. */
export interface BenchmarkRow {
  nameKey: MessageKey
  before: string
  after: string
  beforeWidth: string
  afterWidth: string
  delta: string | null
  deltaKey: MessageKey | null
}

export const BENCHMARK_BEFORE_VERSION = '0.1.4'
export const BENCHMARK_AFTER_VERSION = '0.1.5'

export const BENCHMARKS: readonly BenchmarkRow[] = [
  {
    nameKey: 'benchTail',
    before: '190 MB',
    after: '12 KB',
    beforeWidth: '100%',
    afterWidth: '3%',
    delta: '−99.99%',
    deltaKey: null,
  },
  {
    nameKey: 'benchScan',
    before: 'O(n²/N)',
    after: 'O(n)',
    beforeWidth: '88%',
    afterWidth: '9%',
    delta: null,
    deltaKey: 'benchDeltaOffsetResume',
  },
  {
    nameKey: 'benchReport',
    before: '2×',
    after: '1×',
    beforeWidth: '72%',
    afterWidth: '36%',
    delta: '−50%',
    deltaKey: null,
  },
  {
    nameKey: 'benchAppend',
    before: '5.723 ms/entry',
    after: '5.7 ms/entry',
    beforeWidth: '60%',
    afterWidth: '58%',
    delta: null,
    deltaKey: 'benchDeltaUnchanged',
  },
]

/** Where the figures come from, printed beside them so nobody reads them as a
 * measurement of the host they are looking at. */
export const BENCHMARK_SOURCE = 'CHANGELOG · 0.1.5'
