// App Store screenshots in the sizes App Store Connect asks for: iPhone 6.9"
// (1320 x 2868) and iPad 13" (2064 x 2752), English and Dutch. The iOS app
// shows the same interface as the web vault, so they are taken from it.
//
//   node appstore.js <server url> <work dir> <output dir>
//
// Run scripts/screenshots.sh instead of calling this directly.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const [server, work, out] = process.argv.slice(2);
const PASSWORD = 'correct-horse-battery-staple-42';
const LOCALES = { en: 'en-US', nl: 'nl-NL' };
const T = {
  en: { signin: 'Sign in to an existing account', signinBtn: 'Sign in', generator: 'Password generator', share: 'Share', family: 'Family' },
  nl: { signin: 'Inloggen op een bestaand account', signinBtn: 'Inloggen', generator: 'Wachtwoordgenerator', share: 'Delen', family: 'Gezin' },
};
const DEVICES = {
  iphone: { viewport: { width: 440, height: 956 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true },
  ipad: { viewport: { width: 1032, height: 1376 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
};
const errors = [];

async function open(browser, locale, device) {
  const ctx = await browser.newContext({ ...DEVICES[device], locale: LOCALES[locale], colorScheme: 'light' });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${locale}/${device}: ${e.message}`));
  await page.goto(server + '/');
  await page.waitForSelector('.card', { timeout: 30000 });
  const t = T[locale];
  const email = fs.readFileSync(path.join(work, locale, 'email'), 'utf8').trim();
  const secretKey = fs.readFileSync(path.join(work, locale, 'secret-key'), 'utf8').trim();
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
  return { ctx, page, t };
}

async function shot(page, locale, name) {
  await page.waitForTimeout(500);
  const dir = path.join(out, LOCALES[locale]);
  fs.mkdirSync(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`) });
  console.log(`  ${LOCALES[locale]}/${name}.png`);
}

(async () => {
  const browser = await chromium.launch();
  for (const locale of Object.keys(LOCALES)) {
    // iPhone: the list, an item with its one-time code, Watchtower.
    let { ctx, page, t } = await open(browser, locale, 'iphone');
    await shot(page, locale, 'iphone-1-items');
    await page.locator('.item-row:has-text("GitHub")').first().click();
    await page.waitForSelector('.detail-head');
    await shot(page, locale, 'iphone-2-item');
    await page.click('.toolbar .mobile-only');
    await page.click('.list-head .mobile-only');
    await page.click('.nav-item:has-text("Watchtower")');
    await page.waitForSelector('.score');
    await shot(page, locale, 'iphone-3-watchtower');
    await ctx.close();

    // iPad: everything side by side, the generator, sharing.
    ({ ctx, page, t } = await open(browser, locale, 'ipad'));
    await page.locator('.item-row:has-text("GitHub")').first().click();
    await page.waitForSelector('.detail-head');
    await shot(page, locale, 'ipad-1-item');
    await page.click(`.nav-item:has-text("${t.generator}")`);
    await page.waitForSelector('.gen-output');
    await shot(page, locale, 'ipad-2-generator');
    await page.click(`.nav-item:has-text("${t.family}")`);
    await page.click(`.list-head button[title="${t.share}"]`);
    await page.waitForSelector('.modal :text("sam@")', { timeout: 15000 });
    await shot(page, locale, 'ipad-3-share');
    await ctx.close();
  }
  await browser.close();
  if (errors.length) {
    console.error('Page errors:\n' + errors.join('\n'));
    process.exit(1);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
