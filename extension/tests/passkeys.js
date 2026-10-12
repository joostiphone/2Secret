// End-to-end test of passkeys in the browser extension: a page on
// http://localhost registers a passkey and signs in with it through 2Secret,
// and checks the signature itself with WebCrypto.
//
//   ./extension/build.sh && xvfb-run node extension/tests/passkeys.js
//
// Needs Playwright with Chromium (extensions need a headed browser, hence xvfb).
const { chromium } = require('playwright');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const ext = path.resolve(__dirname, '../dist');
const page = fs.readFileSync(path.join(__dirname, 'webauthn.html'));
const PW = 'correct-horse-battery-staple-42';

function check(cond, what) {
  if (!cond) throw new Error(`failed: ${what}`);
  console.log(`ok - ${what}`);
}

(async () => {
  const server = http.createServer((_, res) => res.end(page)).listen(0);
  const port = server.address().port;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), '2secret-passkeys-'));
  const ctx = await chromium.launchPersistentContext(profile, {
    headless: false,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  const errors = [];
  ctx.on('page', (p) => p.on('pageerror', (e) => errors.push(e.message)));
  try {
    const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
    const id = new URL(sw.url()).host;

    // A local-only account in the extension.
    const popup = await ctx.newPage();
    await popup.goto(`chrome-extension://${id}/index.html`);
    await popup.click('text=Create a new account');
    const inputs = popup.locator('.card input');
    await inputs.nth(0).fill('Alex');
    await inputs.nth(1).fill('alex@example.com');
    await inputs.nth(2).fill(PW);
    await inputs.nth(3).fill(PW);
    await popup.click('button:has-text("Create account")');
    await popup.waitForSelector('text=Save your Secret Key', { timeout: 60000 });
    await popup.click('.checkbox');
    await popup.click('button:has-text("Open my vault")');
    await popup.waitForSelector('.list-head', { timeout: 30000 });
    await popup.waitForTimeout(1500);

    const site = await ctx.newPage();
    await site.goto(`http://localhost:${port}/`);
    const out = async (pattern) => {
      await site.waitForFunction((p) => new RegExp(p).test(document.getElementById('out').textContent), pattern, {
        timeout: 30000,
      });
      return (await site.textContent('#out')).trim().split('\n').pop();
    };
    const window = async (action, title) => {
      const opened = ctx.waitForEvent('page');
      await action();
      const w = await opened;
      await w.waitForSelector(`text=${title}`, { timeout: 30000 });
      return w;
    };

    let w = await window(() => site.click('#reg'), 'Save passkey?');
    await w.click('button:has-text("Save passkey")');
    check((await out('REGISTER')).startsWith('REGISTERED true'), 'registration has the WebAuthn layout');

    w = await window(() => site.click('#login'), 'Sign in with a passkey');
    await w.click('.choice:has-text("alex@example.com")');
    check((await out('SIGN')) === 'SIGNED IN true', 'sign-in signature verifies with the registered key');

    w = await window(() => site.click('#login'), 'Sign in with a passkey');
    await w.close();
    check((await out('SIGNIN ERROR')).includes('NotAllowedError'), 'closing the window cancels');

    // "Another device" hands the request to the browser: here a virtual
    // security key, which then holds the new passkey.
    const cdp = await ctx.newCDPSession(site);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true },
    });
    await site.evaluate(() => (document.getElementById('out').textContent = ''));
    w = await window(() => site.click('#reg'), 'Save passkey?');
    await w.click('button:has-text("Use another device")');
    check((await out('REGISTER')).startsWith('REGISTERED true'), 'another device hands over to the browser');
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    check(credentials.length === 1, 'the security key got the passkey, not 2Secret');

    await popup.reload();
    await popup.click('.item-row:has-text("Test site")');
    check((await popup.locator('text=Passkeys').count()) > 0, 'the passkey is in the vault');
    check(errors.length === 0, `no page errors ${JSON.stringify(errors)}`);
  } finally {
    await ctx.close();
    server.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
