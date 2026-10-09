import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const directory = resolve(process.env.COMPATLAS_PREVIEW_OUTPUT ?? 'artifacts/preview');
const allowed = new Set(['index.html', 'packages.html', 'finding.html', 'operations.html', 'administration.html', 'site.css']);
const server = createServer(async (request, response) => {
  const file = new URL(request.url, 'http://localhost').pathname.slice(1) || 'index.html';
  if (!allowed.has(file)) { response.writeHead(404).end(); return; }
  try { response.setHeader('Content-Type', file.endsWith('.css') ? 'text/css' : 'text/html'); response.end(await readFile(resolve(directory, file))); }
  catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE || undefined, headless: true });
  const axe = await readFile(resolve('node_modules/axe-core/axe.min.js'), 'utf8');
  const results = [];
  for (const file of [...allowed].filter(file => file.endsWith('.html'))) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    await page.goto(`http://127.0.0.1:${server.address().port}/${file}`);
    await page.addScriptTag({ content: axe });
    const result = await page.evaluate(async () => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'] } }));
    results.push({ page: file, violations: result.violations, incomplete: result.incomplete.map(item => ({ id: item.id, impact: item.impact })) });
    await page.keyboard.press('Tab');
    const first = await page.locator(':focus').textContent();
    if (!first?.includes('Skip to main content')) throw new Error(`Keyboard skip link is not first on ${file}`);
    await page.keyboard.press('Enter');
    const mainFocused = await page.locator(':focus').getAttribute('id');
    if (mainFocused !== 'main') throw new Error(`Skip link does not move focus to main on ${file}`);
    await page.screenshot({ path: resolve(directory, file.replace('.html', '.png')), fullPage: true });
    await page.setViewportSize({ width: 320, height: 700 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    if (overflow) throw new Error(`Page-level horizontal overflow at 320px on ${file}`);
    await page.close();
  }
  await writeFile(resolve(directory, 'accessibility-results.json'), JSON.stringify(results, null, 2));
  const failures = results.flatMap(result => result.violations.map(violation => `${result.page}: ${violation.id}`));
  if (failures.length) throw new Error(failures.join('\n'));
  console.log(`Passed automated axe and keyboard/reflow checks on ${results.length} rendered views. Manual NVDA and deployed Windows Authentication remain unverified.`);
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
