/* Compatibility barrel: callers keep importing from `@/lib/i18n`. */
export {
  LANGS,
  lang,
  message,
  setLang,
  translate,
  useI18n,
} from '../i18n'
export type { I18n, Lang, MessageKey, MessageVars } from '../i18n'
