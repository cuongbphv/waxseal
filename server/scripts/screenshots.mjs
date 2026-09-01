/* Capture every screen of the portal, for server/docs.
 *
 * Driven by `screenshots.sh`, which stands up its own server with its own demo
 * data first. Nothing here reaches a real deployment.
 *
 * Screens that need a run to show anything get the run: Cadence is filled in and
 * submitted, the trail screen's commands are executed, and a chain is selected
 * where one is needed. A screenshot of an empty form says nothing about what the
 * product does — but a screenshot must also not show a result the product did
 * not produce, so every value typed here is a real input and every output is the
 * command's own.
 */

import { chromium } from 'playwright'

const [base, outDir, lang = 'vi'] = process.argv.slice(2)
if (!base || !outDir) {
  console.error('usage: screenshots.mjs <baseUrl> <outDir> [lang]')
  process.exit(2)
}

const DESKTOP = { width: 1440, height: 900 }
const PHONE = { width: 390, height: 844 }

/* Every screen, and what has to happen before it is worth photographing. */
const SHOTS = [
  { name: '01-dashboard', path: '/' },
  { name: '02-trail-entries', path: '/trails/orders/entries' },
  { name: '03-trail-output', path: '/trails/orders/output', run: runFirstCommand },
  { name: '04-trail-sidecars', path: '/trails/orders/sidecars' },
  { name: '05-trail-segments', path: '/trails/orders/segments' },
  { name: '06-receipts', path: '/receipts' },
  { name: '07-preflight', path: '/preflight' },
  { name: '08-consistency', path: '/consistency' },
  { name: '09-handoff', path: '/handoff', run: submitForm },
  { name: '10-tickets', path: '/tickets', run: fillTickets },
  { name: '11-cadence', path: '/cadence', run: fillCadence },
  { name: '12-ledger', path: '/ledger' },
  { name: '13-import', path: '/import' },
  { name: '14-read-api', path: '/read-api' },
  { name: '15-users', path: '/users' },
  { name: '16-keys', path: '/keys' },
  { name: '17-benchmark', path: '/benchmark' },
  { name: '18-integrations', path: '/integrations' },
  { name: '19-settings', path: '/settings' },
]

async function fillCadence(page) {
  // Real measurements for a plausible workload, not placeholders: the output
  // below them is the command's own arithmetic on these exact numbers.
  const values = ['100', '0.5', '1000', '0.01', '2', '60']
  const inputs = await page.$$('.field input')
  for (let i = 0; i < values.length && i < inputs.length; i++) {
    await inputs[i].fill(values[i])
  }
  await submitForm(page)
}

async function fillTickets(page) {
  const inputs = await page.$$('.field input')
  if (inputs[0]) await inputs[0].fill('issuer-a')
  if (inputs[1]) await inputs[1].fill('10')
  await submitForm(page)
}

async function submitForm(page) {
  const button = await page.$('button[type=submit]')
  if (button) {
    await button.click()
    await page.waitForTimeout(2500)
  }
}

async function runFirstCommand(page) {
  // The trail screen runs its command on arriving at the Output tab.
  await page.waitForTimeout(2500)
}

async function setLanguage(page) {
  // The toggle is EN/VI; `vi` is the default, so only `en` needs a click.
  if (lang !== 'en') return
  const buttons = await page.$$('.lang-option')
  for (const b of buttons) {
    if ((await b.innerText()).trim().toUpperCase() === 'EN') {
      await b.click()
      await page.waitForTimeout(400)
      return
    }
  }
}

const browser = await chromium.launch()
const problems = []

for (const [viewport, suffix, full] of [
  [DESKTOP, '', true],
  [PHONE, '-phone', false],
]) {
  const page = await browser.newPage({ viewport, deviceScaleFactor: 2 })
  page.on('pageerror', (e) => problems.push(`${suffix || 'desktop'}: ${e.message.slice(0, 80)}`))

  await page.goto(base + '/', { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(900)
  await setLanguage(page)

  for (const shot of SHOTS) {
    await page.goto(base + shot.path, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1100)
    if (shot.run) await shot.run(page)
    // Settle any late-arriving request before the shutter.
    await page.waitForTimeout(500)

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    )
    if (overflow) problems.push(`${shot.name}${suffix}: horizontal overflow`)

    /* A published frame must not carry a real path, name or credential.
     *
     * This is checked rather than trusted because the leak is invisible in
     * review: every output panel prints the `argv` that produced it, so a
     * developer's home directory ends up rendered into the pixels of a file
     * that then gets committed. Checked on the TEXT, before the shutter — once
     * it is a PNG nobody greps it. */
    const leaks = await page.evaluate(() => {
      const text = document.body.innerText
      const found = []
      for (const [label, re] of [
        ['home path', /\/(?:Users|home)\/[a-z0-9._-]+/i],
        ['api key', /wxs_live_[A-Za-z0-9_-]{8}/],
        ['bearer token', /Bearer\s+[A-Za-z0-9_-]{12}/],
      ]) {
        const m = text.match(re)
        if (m) found.push(`${label}: ${m[0]}`)
      }
      return found
    })
    for (const leak of leaks) problems.push(`${shot.name}${suffix}: ${leak}`)

    const file = `${outDir}/${shot.name}${suffix}.png`
    await page.screenshot({ path: file, fullPage: full })
    console.log(`  ${shot.name}${suffix}${overflow ? '  <-- OVERFLOW' : ''}`)
  }
  await page.close()
}

// The nav drawer only exists at phone width, so it gets its own frame.
const drawer = await browser.newPage({ viewport: PHONE, deviceScaleFactor: 2 })
await drawer.goto(base + '/', { waitUntil: 'domcontentloaded' })
await drawer.waitForTimeout(1000)
await setLanguage(drawer)
await drawer.click('.nav-toggle')
await drawer.waitForTimeout(500)
await drawer.screenshot({ path: `${outDir}/00-nav-phone.png` })
console.log('  00-nav-phone')
await drawer.close()

await browser.close()

if (problems.length) {
  console.error('\nproblems:')
  for (const p of [...new Set(problems)]) console.error('  ' + p)
  process.exit(1)
}
console.log('\nall screens captured with no page errors and no overflow')
