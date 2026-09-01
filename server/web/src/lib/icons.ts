/* The stroked 24×24 icon paths from the delivered design, as data.
 *
 * Icons live here rather than in markup so a nav entry is one line in
 * `nav.ts`: adding Workstream B's segments screen must not mean editing an
 * SVG in a layout component.
 */

export const ICON_PATHS = {
  dashboard: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  import: 'M12 4v10m0 0l-4-4m4 4l4-4M5 19h14',
  preflight: 'M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z',
  ledger: 'M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zM12 12l8-4.5M12 12L4 7.5M12 12v9',
  receipts: 'M7 3h10v18l-2.5-1.5L12 21l-2.5-1.5L7 21V3zM10 8h4M10 12h4',
  api: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z',
  users: 'M12 11a4 4 0 100-8 4 4 0 000 8zM5 21c1-3.5 3.5-5 7-5s6 1.5 7 5',
  keys: 'M15 9a4 4 0 11-4-4 4 4 0 014 4zM11 13L4 20M6 18l2 2',
  bench: 'M5 20v-6M11 20V6M17 20V10M3 20h18',
  int: 'M9 7V4M15 7V4M7 7h10v5a5 5 0 01-10 0V7zM12 17v4',
  signOut: 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9',
  upload: 'M12 4v10m0 0l-4-4m4 4l4-4M5 19h14',
  check: 'M5 13l4 4L19 7',
  menu: 'M4 7h16M4 12h16M4 17h16',
  settings: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 01-2.8 2.8l-.1-.1a1.7 1.7 0 00-2.9 1.2v.2a2 2 0 01-4 0v-.1a1.7 1.7 0 00-2.9-1.2l-.1.1a2 2 0 01-2.8-2.8l.1-.1A1.7 1.7 0 003.6 15H3.4a2 2 0 010-4h.2a1.7 1.7 0 001.2-2.9l-.1-.1a2 2 0 012.8-2.8l.1.1A1.7 1.7 0 0010.5 4V3.8a2 2 0 014 0V4a1.7 1.7 0 002.9 1.2l.1-.1a2 2 0 012.8 2.8l-.1.1A1.7 1.7 0 0020.4 11h.2a2 2 0 010 4h-.2a1.7 1.7 0 00-1 .1z',
  close: 'M6 6l12 12M18 6L6 18',
  cadence: 'M4 18h4l3-9 3 13 3-11 2 7h2',
  handoff: 'M4 8h9m0 0l-3-3m3 3l-3 3M20 16h-9m0 0l3-3m-3 3l3 3',
  tickets: 'M4 8a2 2 0 012-2h12a2 2 0 012 2 2 2 0 000 4 2 2 0 000 4 2 2 0 01-2 2H6a2 2 0 01-2-2 2 2 0 000-4 2 2 0 000-4zM12 8v8',
  proof: 'M9 12l2 2 4-4M7 3h10a2 2 0 012 2v14a2 2 0 01-2 2H7a2 2 0 01-2-2V5a2 2 0 012-2z',
  external: 'M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5',
} as const

export type IconKey = keyof typeof ICON_PATHS
