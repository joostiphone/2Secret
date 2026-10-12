// Takes the screenshots in docs/screenshots from a running web vault that was
// filled by seed.sh, and writes docs/screenshots/manifest.json.
//
//   node shoot.js <server url> <work dir> <output dir>
//
// Needs Playwright with Chromium. Run scripts/screenshots.sh instead of
// calling this directly.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const [server, work, out] = process.argv.slice(2);
const PASSWORD = 'correct-horse-battery-staple-42';
const account = (locale) => ({
  email: fs.readFileSync(path.join(work, locale, 'email'), 'utf8').trim(),
  secretKey: fs.readFileSync(path.join(work, locale, 'secret-key'), 'utf8').trim(),
});

const T = {
  en: { signin: 'Sign in to an existing account', signinBtn: 'Sign in', create: 'Create a new account',
        createBtn: 'Create account', saveKey: 'Save your Secret Key', generator: 'Password generator',
        share: 'Share', unlock: 'Unlock', family: 'Family' },
  nl: { signin: 'Inloggen op een bestaand account', signinBtn: 'Inloggen', create: 'Nieuw account aanmaken',
        createBtn: 'Account aanmaken', saveKey: 'Bewaar je geheime sleutel', generator: 'Wachtwoordgenerator',
        share: 'Delen', unlock: 'Ontgrendelen', family: 'Gezin' },
};

// name -> [English title, Dutch title, device]
const SHOTS = {
  welcome: ['Welcome screen', 'Welkomstscherm', 'desktop'],
  'secret-key': ['Your Secret Key and Emergency Kit', 'Je geheime sleutel en noodkit', 'desktop'],
  item: ['Item details with a live one-time code', 'Itemdetails met een live eenmalige code', 'desktop'],
  watchtower: ['Watchtower finds weak, reused and unsafe passwords', 'Watchtower vindt zwakke, hergebruikte en onveilige wachtwoorden', 'desktop'],
  generator: ['Password generator', 'Wachtwoordgenerator', 'desktop'],
  share: ['Sharing a vault, with key fingerprints', 'Een kluis delen, met sleutelvingerafdrukken', 'desktop'],
  locked: ['Locked vault', 'Vergrendelde kluis', 'desktop'],
  'mobile-list': ['All items on a phone', 'Alle items op een telefoon', 'mobile'],
  'mobile-item': ['Item details on a phone', 'Itemdetails op een telefoon', 'mobile'],
};

const manifest = [];
const errors = [];

async function context(browser, locale, theme, device) {
  const mobile = device === 'mobile';
  const ctx = await browser.newContext({
    viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    isMobile: mobile,
    hasTouch: mobile,
    locale: locale === 'nl' ? 'nl-NL' : 'en-US',
    colorScheme: theme,
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${locale}/${theme}: ${e.message}`));
  await page.goto(server + '/');
  await page.waitForSelector('.card', { timeout: 30000 });
  return { ctx, page };
}

async function shot(page, locale, theme, name) {
  await page.waitForTimeout(400);
  const file = `${locale}-${theme}-${name}.png`;
  await page.screenshot({ path: path.join(out, file) });
  const [en, nl, device] = SHOTS[name];
  manifest.push({ file, title_en: en, title_nl: nl, theme, locale, device });
  console.log('  ' + file);
}

async function signIn(page, t, locale) {
  const { email, secretKey } = account(locale);
  await page.click(`text=${t.signin}`);
  const inputs = page.locator('.card input');
  await inputs.first().waitFor();
  if (!(await inputs.nth(0).inputValue())) await inputs.nth(0).fill(server);
  await inputs.nth(1).fill(email);
  await inputs.nth(2).fill(secretKey);
  await inputs.nth(3).fill(PASSWORD);
  await page.click(`.card button:has-text("${t.signinBtn}")`);
  await page.waitForSelector('.item-row', { timeout: 60000 });
  await page.waitForTimeout(800);
}

(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  for (const locale of ['en', 'nl']) {
    const t = T[locale];
    for (const theme of ['light', 'dark']) {
      console.log(`${locale} ${theme}`);

      // Onboarding: welcome screen and a new account's Secret Key.
      let { ctx, page } = await context(browser, locale, theme, 'desktop');
      await shot(page, locale, theme, 'welcome');
      await page.click(`text=${t.create}`);
      const inputs = page.locator('.card input');
      await inputs.nth(0).fill(locale === 'nl' ? 'Alex de Vries' : 'Alex Morgan');
      await inputs.nth(1).fill(`alex.${locale}.${theme}@example.com`);
      await inputs.nth(2).fill(PASSWORD);
      await inputs.nth(3).fill(PASSWORD);
      await page.click(`button:has-text("${t.createBtn}")`);
      await page.waitForSelector(`text=${t.saveKey}`, { timeout: 60000 });
      await shot(page, locale, theme, 'secret-key');
      await ctx.close();

      // The demo account on the desktop.
      ({ ctx, page } = await context(browser, locale, theme, 'desktop'));
      await signIn(page, t, locale);
      await page.locator('.item-row:has-text("GitHub")').first().click();
      await page.waitForSelector('.detail-head');
      await shot(page, locale, theme, 'item');
      await page.click('.nav-item:has-text("Watchtower")');
      await page.waitForSelector('.score');
      await shot(page, locale, theme, 'watchtower');
      await page.click(`.nav-item:has-text("${t.generator}")`);
      await page.waitForSelector('.gen-output');
      await shot(page, locale, theme, 'generator');
      await page.click(`.nav-item:has-text("${t.family}")`);
      await page.click(`.list-head button[title="${t.share}"]`);
      await page.waitForSelector('.modal');
      await page.waitForSelector('.modal :text("sam@")', { timeout: 15000 });
      await shot(page, locale, theme, 'share');
      await page.keyboard.press('Escape');
      await page.click('.sidebar-head button');
      await page.waitForSelector(`button:has-text("${t.unlock}")`);
      await shot(page, locale, theme, 'locked');
      await ctx.close();

      // The demo account on a phone.
      ({ ctx, page } = await context(browser, locale, theme, 'mobile'));
      await signIn(page, t, locale);
      await shot(page, locale, theme, 'mobile-list');
      await page.locator('.item-row:has-text("GitHub")').first().click();
      await page.waitForSelector('.detail-head');
      await shot(page, locale, theme, 'mobile-item');
      await ctx.close();
    }
  }
  await browser.close();
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  if (errors.length) {
    console.error('Page errors:\n' + errors.join('\n'));
    process.exit(1);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
