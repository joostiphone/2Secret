// The app screens for the App Store screenshots, English and Dutch: iPhone
// (440 x 956 points at 3x) and iPad 13" (1032 x 1376 points at 2x). The iOS app
// shows the same interface as the web vault, so the screens are taken from it,
// with the iOS status bar and home indicator around them.
// scripts/screenshots/appstore-compose.js then puts them in the designs.
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
  en: {
    create: 'Create a new account', signin: 'Sign in to an existing account', signinBtn: 'Sign in',
    generator: 'Password generator', share: 'Share', family: 'Family', ourServer: '2Secret server',
    name: 'Alex Morgan', email: 'alex@example.com',
  },
  nl: {
    create: 'Nieuw account aanmaken', signin: 'Inloggen op een bestaand account', signinBtn: 'Inloggen',
    generator: 'Wachtwoordgenerator', share: 'Delen', family: 'Gezin', ourServer: '2Secret-server',
    name: 'Alex de Vries', email: 'alex@voorbeeld.nl',
  },
};
// Screen size in points, scale, and the status bar (top) and home indicator
// (bottom). On the iPhone the app runs on under them (`under`); on the iPad it
// keeps clear of them.
const DEVICES = {
  iphone: { width: 440, height: 956, scale: 3, top: 62, bottom: 34, under: true },
  ipad: { width: 1032, height: 1376, scale: 2, top: 24, bottom: 20 },
};
const errors = [];

async function context(browser, locale, device) {
  const d = DEVICES[device];
  return browser.newContext({
    viewport: { width: d.width, height: d.under ? d.height : d.height - d.top },
    deviceScaleFactor: d.scale, isMobile: true, hasTouch: true, locale: LOCALES[locale], colorScheme: 'light',
    bypassCSP: true,
  });
}

// The safe area (env(safe-area-inset-*), 0 in a browser) through its
// variables in style.css.
async function load(page, device) {
  const d = DEVICES[device];
  await page.goto(server + '/');
  await page.waitForSelector('.card', { timeout: 30000 });
  await page.addStyleTag({ content: `.root { --safe-top: ${d.under ? d.top : 0}px !important; --safe-bottom: ${d.bottom}px !important; }` });
}

async function signIn(browser, locale, device) {
  const ctx = await context(browser, locale, device);
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${locale}/${device}: ${e.message}`));
  await load(page, device);
  const t = T[locale];
  await page.click(`text=${t.signin}`);
  const inputs = page.locator('.card input');
  await inputs.first().waitFor();
  if (!(await inputs.nth(0).inputValue())) await inputs.nth(0).fill(server);
  await inputs.nth(1).fill(fs.readFileSync(path.join(work, locale, 'email'), 'utf8').trim());
  await inputs.nth(2).fill(fs.readFileSync(path.join(work, locale, 'secret-key'), 'utf8').trim());
  await inputs.nth(3).fill(PASSWORD);
  await page.click(`.card button:has-text("${t.signinBtn}")`);
  await page.waitForSelector('.dash', { timeout: 60000 });
  await page.waitForTimeout(1500);
  return { ctx, page, t };
}

// Opens a section from the sidebar, which on a phone first has to slide in.
async function nav(page, device, label) {
  if (device === 'iphone') {
    await page.click('.toolbar .mobile-only:not(.back), .list-head .mobile-only');
    await page.waitForSelector('.nav-item', { state: 'visible' });
  }
  await page.click(`.nav-item:has-text("${label}")`);
}

async function openItem(page, title) {
  await page.locator(`.item-row:has-text("${title}")`).first().click();
  await page.waitForSelector('.detail-head');
  // Show a one-time password with most of its 30 seconds still to go.
  while (Math.floor(Date.now() / 1000) % 30 > 3) await page.waitForTimeout(250);
}

// Puts the status bar over a capture of the app (above it on the iPad, on the
// colours of the app's top edge) and the home indicator over its bottom edge,
// as on a device.
async function frame(browser, png, device, file) {
  const d = DEVICES[device];
  const page = await browser.newPage({ viewport: { width: d.width, height: d.height }, deviceScaleFactor: d.scale });
  const src = 'data:image/png;base64,' + fs.readFileSync(png).toString('base64');
  await page.setContent(SCREEN_HTML);
  await page.evaluate(({ src, d, ipad }) => window.draw(src, d, ipad), { src, d, ipad: device === 'ipad' });
  await page.waitForFunction(() => window.done === true);
  await page.screenshot({ path: file });
  await page.close();
}

const SCREEN_HTML = `<!doctype html><html><head><style>
  html, body { margin: 0; height: 100%; overflow: hidden; }
  body { font-family: Inter, -apple-system, sans-serif; position: relative; }
  canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
  .bar { position: absolute; left: 0; right: 0; top: 0; display: flex; align-items: center; justify-content: space-between; }
  .bar span { font-weight: 600; letter-spacing: -.01em; }
  .bar svg { display: block; }
  .icons { display: flex; align-items: center; }
  .home { position: absolute; left: 50%; transform: translateX(-50%); border-radius: 99px; }
</style></head><body><canvas id="c"></canvas>
<div class="bar"><div class="left"><span id="time">9:41</span></div><div class="icons" id="icons"></div></div>
<div class="home" id="home"></div>
<script>
const SIGNAL = (c) => '<svg width="19" height="12" viewBox="0 0 19 12"><g fill="' + c + '"><rect x="0" y="7.5" width="3.2" height="4.5" rx="1"/><rect x="5" y="5" width="3.2" height="7" rx="1"/><rect x="10" y="2.5" width="3.2" height="9.5" rx="1"/><rect x="15" y="0" width="3.2" height="12" rx="1"/></g></svg>';
const WIFI = (c) => '<svg width="17" height="12" viewBox="0 0 17 12"><g fill="' + c + '"><path d="M8.5 2.6c2.4 0 4.6.9 6.3 2.5l1.2-1.2C14 2 11.4.9 8.5.9S3 2 1 3.9l1.2 1.2C3.9 3.5 6.1 2.6 8.5 2.6z"/><path d="M8.5 6.1c1.4 0 2.7.5 3.7 1.4l1.2-1.2c-1.3-1.2-3-1.9-4.9-1.9s-3.6.7-4.9 1.9l1.2 1.2c1-.9 2.3-1.4 3.7-1.4z"/><path d="M8.5 9.4c.5 0 .9.2 1.2.5L8.5 11.2 7.3 9.9c.3-.3.7-.5 1.2-.5z"/></g></svg>';
const BATTERY = (c) => '<svg width="27" height="13" viewBox="0 0 27 13"><rect x=".5" y=".5" width="23" height="12" rx="3.6" fill="none" stroke="' + c + '" stroke-opacity=".4"/><rect x="2" y="2" width="20" height="9" rx="2.2" fill="' + c + '"/><path d="M25 4.4v4.2c.8-.3 1.4-1.1 1.4-2.1s-.6-1.8-1.4-2.1z" fill="' + c + '" fill-opacity=".45"/></svg>';
function light(ctx, x, y) {
  const [r, g, b] = ctx.getImageData(x, y, 1, 1).data;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 140;
}
window.draw = (src, d, ipad) => {
  const img = new Image();
  img.onload = () => {
    const c = document.getElementById('c'), s = d.scale;
    c.width = d.width * s; c.height = d.height * s;
    const ctx = c.getContext('2d');
    const top = d.top * s, bottom = d.bottom * s;
    if (d.under) {
      ctx.drawImage(img, 0, 0);
    } else {
      ctx.drawImage(img, 0, 0, img.width, 1, 0, 0, c.width, top);
      ctx.drawImage(img, 0, top);
    }
    const bar = document.querySelector('.bar'), icons = document.getElementById('icons');
    const leftInk = light(ctx, Math.round(40 * s), Math.round(top / 2)) ? '#000' : '#fff';
    const rightInk = light(ctx, c.width - Math.round(40 * s), Math.round(top / 2)) ? '#000' : '#fff';
    const time = document.getElementById('time');
    time.style.color = leftInk;
    if (ipad) {
      bar.style.height = d.top + 'px'; bar.style.padding = '0 22px 0 24px';
      time.style.fontSize = '14px';
      time.textContent = '9:41';
      icons.innerHTML = WIFI(rightInk) + '<span style="width:6px"></span><span style="font-size:13px;color:' + rightInk + '">100%</span><span style="width:5px"></span>' + BATTERY(rightInk);
    } else {
      bar.style.height = d.top + 'px'; bar.style.padding = '0 34px 0 52px';
      time.style.fontSize = '17px';
      icons.innerHTML = SIGNAL(rightInk) + '<span style="width:6px"></span>' + WIFI(rightInk) + '<span style="width:6px"></span>' + BATTERY(rightInk);
    }
    const home = document.getElementById('home');
    const homeLight = light(ctx, Math.round(c.width / 2), c.height - Math.round(bottom / 2));
    home.style.background = homeLight ? '#000' : '#fff';
    home.style.width = (ipad ? 320 : 146) + 'px'; home.style.height = '5px';
    home.style.bottom = (ipad ? 7 : 8) + 'px';
    document.fonts.ready.then(() => { window.done = true; });
  };
  img.src = src;
};
</script></body></html>`;

(async () => {
  const browser = await chromium.launch();
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'appstore-'));
  for (const locale of Object.keys(LOCALES)) {
    const dir = path.join(out, LOCALES[locale]);
    fs.mkdirSync(dir, { recursive: true });
    for (const device of Object.keys(DEVICES)) {
      let n = 0;
      const { ctx, page, t } = await signIn(browser, locale, device);
      const shot = async (name) => {
        await page.waitForTimeout(600);
        const raw = path.join(tmp, 'raw.png');
        await page.screenshot({ path: raw });
        const file = path.join(dir, `${device}-${++n}-${name}.png`);
        await frame(browser, raw, device, file);
        console.log(`  ${path.relative(out, file)}`);
      };

      if (device === 'iphone') {
        await shot('dashboard');
        await openItem(page, 'GitHub');
        await shot('item');
        await page.click('.toolbar .mobile-only.back');
      } else {
        await nav(page, device, 'Watchtower');
        await nav(page, device, LOCALES[locale] === 'nl-NL' ? 'Alle items' : 'All items');
        await openItem(page, 'GitHub');
        await shot('item');
        await nav(page, device, 'Dashboard');
        await page.waitForSelector('.dash');
        await shot('dashboard');
      }
      await nav(page, device, 'Watchtower');
      await page.waitForSelector('.score');
      await shot('watchtower');
      await nav(page, device, t.generator);
      await page.waitForSelector('.gen-output');
      await shot('generator');
      await nav(page, device, t.family);
      await page.click(`.list-head button[title="${t.share}"]`);
      await page.waitForSelector('.modal .fingerprint, .modal .mono', { timeout: 15000 });
      await shot('share');
      await ctx.close();

      {
        // Creating an account: where the vault syncs is the user's choice.
        const c = await context(browser, locale, device);
        const p = await c.newPage();
        await load(p, device);
        await p.click(`text=${t.create}`);
        const inputs = p.locator('.card input');
        await inputs.first().waitFor();
        await inputs.nth(0).fill(t.name);
        await inputs.nth(1).fill(t.email);
        await inputs.nth(2).fill('purple-orbit-canyon-lantern');
        await inputs.nth(3).fill('purple-orbit-canyon-lantern');
        await p.click(`.card .choice:has-text("${t.ourServer}")`);
        await p.locator('.card .choice').last().evaluate((e) => e.scrollIntoView({ block: 'end' }));
        await p.evaluate(() => window.scrollBy(0, 40));
        await p.evaluate(() => document.activeElement && document.activeElement.blur());
        await p.waitForTimeout(600);
        const raw = path.join(tmp, 'raw.png');
        await p.screenshot({ path: raw });
        const file = path.join(dir, `${device}-${++n}-create.png`);
        await frame(browser, raw, device, file);
        console.log(`  ${path.relative(out, file)}`);
        await c.close();
      }
    }
  }
  await browser.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  if (errors.length) {
    console.error('Page errors:\n' + errors.join('\n'));
    process.exit(1);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
