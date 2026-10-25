// End-to-end test of agentic autofill in the browser extension: a fake
// native messaging host (standing in for the 2Secret app) hands the
// extension a login, the extension fills the sign-in page that is the active
// tab, submits it, and reports back. Also checks that nothing is filled in a
// tab of another site, and what is reported when the page has no fields.
//
//   ./extension/build.sh && xvfb-run node extension/tests/fill.js
//
// Needs Playwright with Chromium (extensions need a headed browser, hence
// xvfb) and Node for the fake host. The extension's manifest holds its key,
// so its id is fixed and the host manifest can be written before the browser
// starts.
const { chromium } = require('playwright');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const ext = path.resolve(__dirname, '../dist');
const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));
const loginPage = fs.readFileSync(path.join(__dirname, 'login.html'));
const HOST_NAME = 'io.github.joostiphone.twosecret';
const EXTENSION_ID = 'gnkfgnlegljjfnihdefkjepdoaphccfd';

function check(cond, what) {
  if (!cond) throw new Error(`failed: ${what}`);
  console.log(`ok - ${what}`);
}

async function waitFor(fn, what, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out: ${what}`);
}

// The fake host: speaks the browser's framing on stdin/stdout, sends
// `status` after the extension's `hello`, then a `fill` as soon as the test
// creates the trigger file, and writes every frame it receives to a log.
function fakeHost(dir, port, logFile, triggerFile) {
  const script = `
const fs = require('fs');
const log = (v) => fs.appendFileSync(${JSON.stringify(logFile)}, JSON.stringify(v) + '\\n');
const send = (v) => { const b = Buffer.from(JSON.stringify(v)); const l = Buffer.alloc(4); l.writeUInt32LE(b.length); process.stdout.write(Buffer.concat([l, b])); };
let buf = Buffer.alloc(0);
let sent = false;
process.stdin.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  while (buf.length >= 4) {
    const n = buf.readUInt32LE(0);
    if (buf.length < 4 + n) break;
    const msg = JSON.parse(buf.subarray(4, 4 + n).toString());
    buf = buf.subarray(4 + n);
    log(msg);
    if (msg.type === 'hello') {
      send({ type: 'status', app: true, version: 'test' });
      const timer = setInterval(() => {
        if (sent) return clearInterval(timer);
        if (fs.existsSync(${JSON.stringify(triggerFile)})) {
          sent = true;
          clearInterval(timer);
          send({ type: 'fill', id: 'f-1', url: 'http://localhost:${port}/', submit: true,
            rules: [{ domain: 'localhost', https: false, port: ${port}, exact: false }],
            username: 'octo', password: 'hunter2', code: '' });
        }
      }, 100);
    }
  }
});
process.stdin.on('end', () => process.exit(0));
setInterval(() => send({ type: 'ping' }), 5000);
`;
  const scriptPath = path.join(dir, 'fake-host.js');
  fs.writeFileSync(scriptPath, script);
  const launcher = path.join(dir, 'fake-host.sh');
  fs.writeFileSync(launcher, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(scriptPath)} "$@"\n`, { mode: 0o755 });
  return launcher;
}

(async () => {
  check(Array.isArray(manifest.permissions) && manifest.permissions.includes('nativeMessaging'), 'the manifest asks for nativeMessaging');
  check(manifest.permissions.includes('alarms'), 'the manifest asks for alarms');
  check(manifest.background.scripts[0] === 'fill.js', 'Firefox loads fill.js before background.js');
  check(fs.existsSync(path.join(ext, 'fill.js')), 'fill.js is in the build');
  check(fs.readFileSync(path.join(ext, 'index.html'), 'utf8').includes('src="./fill.js"'), 'the popup loads fill.js');

  const posts = [];
  const server = http
    .createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/done') {
        let body = '';
        req.on('data', (d) => (body += d));
        req.on('end', () => {
          posts.push(body);
          res.setHeader('Content-Type', 'text/html');
          res.end('<!doctype html><title>Done</title><h1 id="done">DONE</h1>');
        });
        return;
      }
      res.setHeader('Content-Type', 'text/html');
      if (req.url === '/nothing') return res.end('<!doctype html><title>Nothing</title><p>No form here.</p>');
      res.end(loginPage);
    })
    .listen(0);
  const port = server.address().port;

  const work = fs.mkdtempSync(path.join(os.tmpdir(), '2secret-fill-'));
  const profile = path.join(work, 'profile');
  const home = path.join(work, 'home');
  fs.mkdirSync(profile);
  fs.mkdirSync(home);
  const logFile = path.join(work, 'host.log');
  const triggerFile = path.join(work, 'go');
  const launcher = fakeHost(work, port, logFile, triggerFile);
  const hostManifest = JSON.stringify({
    name: HOST_NAME,
    description: 'fake 2Secret',
    path: launcher,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
  });
  // Chromium looks in its user data directory (and the default one under
  // HOME, which is where the app writes it).
  for (const dir of [path.join(profile, 'NativeMessagingHosts'), path.join(home, '.config/chromium/NativeMessagingHosts')]) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${HOST_NAME}.json`), hostManifest);
  }

  const ctx = await chromium.launchPersistentContext(profile, {
    headless: false,
    env: { ...process.env, HOME: home },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  const errors = [];
  ctx.on('page', (p) => p.on('pageerror', (e) => errors.push(e.message)));
  try {
    const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
    check(new URL(sw.url()).host === EXTENSION_ID, `the key in the manifest gives the id ${EXTENSION_ID}`);

    // The worker connected to the host by itself and said hello.
    const hello = await waitFor(() => {
      if (!fs.existsSync(logFile)) return null;
      return fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).find((m) => m.type === 'hello');
    }, 'the extension says hello to the host');
    check(hello.extension === manifest.version, 'hello carries the extension version');
    check(['chrome', 'chromium'].includes(hello.browser), `hello names the browser (${hello.browser})`);
    const status = await waitFor(async () => {
      const v = await sw.evaluate(async () => (await chrome.storage.session.get('2s-app'))['2s-app']);
      return v ? JSON.parse(v) : null;
    }, 'the status frame arrives');
    check(status.app === true, 'the extension knows the app is there');

    // A sign-in page as the active tab, and the host sends the login.
    const site = await ctx.newPage();
    await site.goto(`http://localhost:${port}/`);
    await site.bringToFront();
    fs.writeFileSync(triggerFile, '');
    await site.waitForSelector('#done', { timeout: 20000 });
    check(posts.length === 1 && posts[0] === 'user=octo&pw=hunter2', `the form was filled and submitted (${posts[0]})`);
    const result = await waitFor(() => {
      return fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).find((m) => m.type === 'fill_result');
    }, 'the host hears the outcome');
    check(result.id === 'f-1' && result.outcome === 'filled' && result.submitted === true, 'the outcome is filled and submitted');

    // Straight into the handler: a page without fields, and a tab of another site.
    const fill = async (cmd) => sw.evaluate((c) => globalThis.twosecretHandleFill(c), cmd);
    const rules = [{ domain: 'localhost', https: false, port, exact: false }];
    await site.goto(`http://localhost:${port}/nothing`);
    await site.bringToFront();
    let out = await fill({ id: 'f-2', url: `http://localhost:${port}/`, rules, username: 'octo', password: 'hunter2', code: '', submit: true });
    check(out.outcome === 'nothing' && !out.submitted, 'a page without fields reports nothing');

    const other = await ctx.newPage();
    await other.goto(`http://127.0.0.1:${port}/`);
    await other.bringToFront();
    await site.close();
    out = await fill({ id: 'f-3', url: `http://localhost:${port}/`, rules, username: 'octo', password: 'hunter2', code: '', submit: true });
    check(out.outcome === 'no_tab', 'a tab of another site is never filled');
    check((await other.inputValue('input[name=pw]')) === '', 'the other site got no password');

    // Filling without submitting leaves the page where it is.
    const again = await ctx.newPage();
    await again.goto(`http://localhost:${port}/`);
    await again.bringToFront();
    out = await fill({ id: 'f-4', url: `http://localhost:${port}/`, rules, username: 'octo', password: 'hunter2', code: '', submit: false });
    check(out.outcome === 'filled' && out.submitted === false, 'filling without submitting');
    check((await again.inputValue('input[name=user]')) === 'octo', 'the user name is in the field');
    check((await again.inputValue('input[name=pw]')) === 'hunter2', 'the password is in the field');
    check(posts.length === 1, 'nothing more was submitted');
    check(errors.length === 0, `no page errors ${JSON.stringify(errors)}`);
  } finally {
    await ctx.close();
    server.close();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
