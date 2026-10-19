// The App Store screenshots: ios/AppStore/design/template.html with the
// captions in ios/AppStore/design/slides.json and the app screens in
// ios/AppStore/design/screens, at every size App Store Connect asks for,
// written to ios/AppStore/screenshots/<language>/.
//
//   node appstore-compose.js
//
// scripts/screenshots.sh runs it after taking the screens; run it on its own
// after changing a caption or the design.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const design = path.join(root, 'ios/AppStore/design');
const out = path.join(root, 'ios/AppStore/screenshots');
const LOCALES = { en: 'en-US', nl: 'nl-NL' };
// The display sizes in App Store Connect, in pixels.
const SIZES = {
  iphone: { 'iphone-6.9': [1320, 2868], 'iphone-6.3': [1206, 2622] },
  ipad: { 'ipad-13': [2064, 2752] },
};
const slides = JSON.parse(fs.readFileSync(path.join(design, 'slides.json'), 'utf8'));

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file://' + path.join(design, 'template.html'));
  fs.rmSync(out, { recursive: true, force: true });
  for (const [lang, locale] of Object.entries(LOCALES)) {
    fs.mkdirSync(path.join(out, locale), { recursive: true });
    for (const device of Object.keys(SIZES)) {
      const series = slides[device].map((slide, index) => ({
        device, index, hero: !!slide.hero, copy: slide[lang], name: slide.screen.replace(/^[a-z]+-\d+-/, ''),
        screen: `screens/${locale}/${slide.screen}.png`,
      }));
      // One title size for the whole series: the largest at which all fit.
      const [w, h] = Object.values(SIZES[device])[0];
      let title = Infinity;
      for (const s of series) {
        await page.setViewportSize({ width: w, height: h });
        title = Math.min(title, await page.evaluate((s) => window.render(s), { ...s, width: w, height: h }));
      }
      console.log(`${locale} ${device}: titles at ${title} px`);
      for (const [size, [width, height]] of Object.entries(SIZES[device])) {
        await page.setViewportSize({ width, height });
        for (const s of series) {
          await page.evaluate((s) => window.render(s), { ...s, width, height, title });
          const file = path.join(out, locale, `${size}-${s.index + 1}-${s.name}.jpg`);
          await page.screenshot({ path: file, type: 'jpeg', quality: 92, clip: { x: 0, y: 0, width, height } });
          console.log(`  ${path.relative(root, file)}`);
        }
      }
    }
  }
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
