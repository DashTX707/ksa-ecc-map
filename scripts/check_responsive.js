// Real-browser responsive check (Playwright/Chromium).
// Loads docs/index.html at phone->desktop widths, in both tabs and both
// frameworks, with a control expanded, and FAILS (exit 1) if any element
// overflows the viewport horizontally. This is the "actually run the browser"
// gate — a page is not "responsive" until measured, not reasoned about.
//
// Deps (dev/CI only):  npm i playwright && npx playwright install chromium
// Run:                 node scripts/check_responsive.js
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); }
catch (e) {
  console.error('SKIP: playwright not installed (npm i playwright && npx playwright install chromium).');
  process.exit(2); // distinct code: "could not run", not "passed"
}

const PAGE = 'file:///' + path.resolve(__dirname, '..', 'docs', 'index.html').split(path.sep).join('/');
const WIDTHS = [320, 360, 390, 414, 768, 1024, 1280];

async function measure(page) {
  return await page.evaluate(() => {
    const de = document.documentElement, vw = de.clientWidth;
    let worst = null;
    document.querySelectorAll('*').forEach(el => {
      const r = el.getBoundingClientRect();
      if (r.right > vw + 1 && (!worst || r.right > worst.right)) {
        const cls = (typeof el.className === 'string' && el.className) ? '.' + el.className.trim().split(/\s+/).join('.') : '';
        worst = { sel: el.tagName.toLowerCase() + cls, right: Math.round(r.right) };
      }
    });
    return { overflow: de.scrollWidth - vw, worst };
  });
}

(async () => {
  const browser = await chromium.launch();
  let failed = false;
  console.log('viewport | ctrl | tech | cscc | expanded | worst');
  for (const w of WIDTHS) {
    const ctx = await browser.newContext({ viewport: { width: w, height: 900 } });
    const p = await ctx.newPage();
    await p.goto(PAGE, { waitUntil: 'networkidle' }).catch(() => {});
    await p.waitForTimeout(250);
    const ctrl = await measure(p);
    await p.click('#tab-t').catch(() => {}); await p.waitForTimeout(120);
    const tech = await measure(p);
    const fw = await p.$$('.fwbtn'); if (fw[1]) { await fw[1].click(); await p.waitForTimeout(120); }
    const cscc = await measure(p);
    await p.click('#tab-c').catch(() => {}); await p.waitForTimeout(100);
    await p.evaluate(() => { const h = document.querySelector('.ctrl-h'); if (h) h.click(); });
    await p.waitForTimeout(100);
    const expanded = await measure(p);
    const states = { ctrl, tech, cscc, expanded };
    const worst = Object.values(states).map(s => s.worst).filter(Boolean).sort((a, b) => b.right - a.right)[0];
    const ovf = Math.max(...Object.values(states).map(s => s.overflow));
    if (ovf > 1) failed = true;
    console.log(`${String(w).padStart(4)}px | ${String(ctrl.overflow).padStart(4)} | ${String(tech.overflow).padStart(4)} | ${String(cscc.overflow).padStart(4)} | ${String(expanded.overflow).padStart(4)} | ${ovf > 1 && worst ? worst.sel + ' @' + worst.right : 'ok'}`);
    await ctx.close();
  }
  await browser.close();
  console.log(failed ? '\nFAIL: horizontal overflow detected.' : '\nPASS: no horizontal overflow at any width/state.');
  process.exit(failed ? 1 : 0);
})();
