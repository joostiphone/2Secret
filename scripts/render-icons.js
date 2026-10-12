// Renders the app icons from the SVG sources in crates/app/assets.
//
//   node scripts/render-icons.js      (needs Playwright with Chromium, and ImageMagick for the .ico)
//
// icon.svg       – rounded tile with macOS margins: 512/1024 px bundle icons, README logo
// icon-small.svg – nearly full-bleed tile for small sizes: window, Windows .ico,
//                  browser extension and favicon
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const assets = path.join(root, 'crates', 'app', 'assets');
const pub = path.join(root, 'crates', 'app', 'public');

async function render(page, svgFile, size, out) {
  const svg = fs.readFileSync(path.join(assets, svgFile), 'utf8');
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(
    `<html><body style="margin:0;background:transparent">` +
      svg.replace(/width="1024" height="1024"/, `width="${size}" height="${size}"`) +
      `</body></html>`,
  );
  await page.screenshot({ path: out, omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (const size of [512, 1024]) await render(page, 'icon.svg', size, path.join(assets, `icon-${size}.png`));
  for (const size of [16, 32, 64, 128, 256]) await render(page, 'icon-small.svg', size, path.join(assets, `icon-${size}.png`));
  await render(page, 'icon.svg', 512, path.join(root, 'assets', 'logo.png'));

  fs.mkdirSync(pub, { recursive: true });
  await render(page, 'icon-small.svg', 180, path.join(pub, 'apple-touch-icon.png'));
  fs.copyFileSync(path.join(assets, 'icon-32.png'), path.join(pub, 'favicon-32.png'));

  const tmp48 = path.join(require('os').tmpdir(), 'icon-48.png');
  await render(page, 'icon-small.svg', 48, tmp48);
  await browser.close();

  const ico = [16, 32, 64, 128, 256].map((s) => path.join(assets, `icon-${s}.png`));
  ico.splice(2, 0, tmp48);
  execFileSync('convert', [...ico, path.join(assets, 'icon.ico')]);
  execFileSync('convert', [ico[0], ico[1], tmp48, path.join(pub, 'favicon.ico')]);
  console.log('Icons rendered.');
})();
