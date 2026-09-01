import { createApp } from 'vue'
import App from './App.vue'
import { router } from './router'
import { lang, setLang } from './lib/i18n'
import { loadScope, loadServerFacts, watchTokenForRefresh } from './services/serverFacts'
import './styles/base.css'

/* Reflect the stored choice onto the document before first paint, so the
 * `lang` attribute is right for a screen reader on the very first screen. */
setLang(lang.value)

void loadServerFacts()
void loadScope()
watchTokenForRefresh()

createApp(App).use(router).mount('#app')
