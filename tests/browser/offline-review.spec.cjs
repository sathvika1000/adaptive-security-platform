const {test, expect} = require('@playwright/test');
const {readFile} = require('node:fs/promises');
const {execFileSync} = require('node:child_process');
const KEY = 'browser-fixture-platform-key';
const ANALYST_KEY = 'browser-fixture-review-key-32-characters';
const headers = {'X-API-Key': KEY};

async function openCapture(page, origin = '') {
  await page.goto(`${origin}/ui`);
  await page.locator('#api-key').fill(KEY);
  await page.getByRole('button', {name: 'Load incidents'}).click();
  await page.getByRole('button', {name: 'Offline captures', exact: true}).click();
  await page.locator('[data-capture-id="sample"]').click();
  await expect(page.locator('#offline-save-review')).toBeEnabled();
}
async function stateFor(request, origin = '') {
  const capture = await request.get(`${origin}/v1/offline-review/captures/sample`, {headers});
  const finding = (await capture.json()).findings[0];
  const path = `${origin}/v1/offline-review/captures/sample/findings/${finding.incident_id}/reviews`;
  return {path, state: await (await request.get(path, {headers})).json()};
}

// These use real Chromium, the real API and a disposable journal, not mocked HTTP responses.
test('shared review, evidence paging, raw XML, conflicts, export and key cleanup', async ({page, request}, testInfo) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  let downloadCount = 0; page.on('download', () => downloadCount += 1);
  await page.goto('/ui');
  await page.locator('#api-key').fill('wrong-key');
  await page.getByRole('button', {name: 'Load incidents'}).click();
  await expect(page.locator('#message')).toContainText('rejected');
  await expect(page.locator('#view-tabs')).toBeHidden();
  await openCapture(page);
  await expect(page.locator('#offline-events .event')).toHaveCount(20);
  await page.locator('#offline-next').click();
  await expect(page.locator('#offline-events .event')).toHaveCount(5);
  await expect(page.locator('#offline-next')).toBeDisabled();
  await page.locator('#offline-prev').click();
  const record = page.locator('#offline-events .event').first();
  await record.locator('summary').click();
  await expect(record.locator('pre')).toContainText('<synthetic-browser-record />');
  await page.locator('#offline-all').click();
  await expect(page.locator('#offline-event-scope')).toContainText('All 25');
  await page.locator('#offline-evidence').click();
  const note = '<img src=x onerror="window.injected=true"> Reviewed original evidence';
  await page.locator('#offline-note').fill(note);
  await page.locator('#offline-disposition').selectOption('suspicious');
  await page.locator('#offline-save-review').click();
  await expect(page.locator('#offline-review-current')).toContainText('suspicious');
  await expect(page.locator('#offline-review-history')).toContainText(note);
  await expect(page.locator('#offline-review-history img')).toHaveCount(0);
  expect(await page.evaluate(() => window.injected)).toBeUndefined();
  await expect(page.locator('#offline-note')).toHaveValue('');
  const loaded = await stateFor(request);
  expect((await request.post(loaded.path, {headers, data: {
    review_key: loaded.state.review_key, expected_revision: loaded.state.revision,
    disposition: 'inconclusive', note: 'Concurrent reviewer assessment',
  }})).status()).toBe(201);
  await page.locator('#offline-note').fill('Draft survives conflict');
  await page.locator('#offline-save-review').click();
  await expect(page.locator('#message')).toContainText('changed');
  await expect(page.locator('#offline-note')).toHaveValue('Draft survives conflict');
  await page.locator('#offline-save-review').click();
  await expect(page.locator('#offline-note')).toHaveValue('');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#offline-export-review').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^sample-[a-f0-9]{12}-review.json$/);
  const artifact = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(artifact.format).toBe('asp.offline-finding-review');
  expect(artifact.binding.evidence).toHaveLength(25);
  expect(artifact.assessment_history.entries[0].note).toBe('Draft survives conflict');
  expect(artifact.scope.original_evtx_included).toBe(false);
  expect(artifact.payload_sha256).toMatch(/^[a-f0-9]{64}$/);
  execFileSync('python', ['-c', `import sys,json,hashlib
artifact=json.load(sys.stdin)
expected=artifact.pop('payload_sha256')
def digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert digest(artifact)==expected
assert digest(artifact['binding'])==artifact['review_key']`], {input: JSON.stringify(artifact)});
  const latest = await stateFor(request);
  await request.post(latest.path, {headers, data: {
    review_key: latest.state.review_key, expected_revision: latest.state.revision,
    disposition: 'inconclusive', note: 'Changed before export',
  }});
  await page.locator('#offline-note').fill('Unsaved export draft');
  await page.locator('#offline-export-review').click();
  await expect(page.locator('#message')).toContainText('changed');
  await expect(page.locator('#offline-note')).toHaveValue('Unsaved export draft');
  expect(downloadCount).toBe(1);
  await page.screenshot({path: testInfo.outputPath('offline-desktop.png'), fullPage: true});
  // New browsing session reads saved data; no browser storage keeps either key.
  await page.reload(); await openCapture(page);
  await expect(page.locator('#offline-review-history')).toContainText('Draft survives conflict');
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.locator('#offline-note').fill('Discard on selection');
  await page.locator('[data-capture-id="thin-sample"]').click();
  await expect(page.locator('#offline-findings')).toContainText('No candidate findings');
  await expect(page.locator('#offline-review-panel')).toBeHidden();
  await expect(page.locator('#offline-events .event')).toHaveCount(2);
  await expect(page.locator('#offline-note')).toHaveValue('');
  await page.getByRole('button', {name: 'Forget key'}).click();
  await expect(page.locator('#offline-workspace')).toBeHidden();
  expect(await page.locator('#offline-review-history').textContent()).toBe('');
  expect(errors).toEqual([]);
});

test('named analyst permission and attribution work in the browser', async ({page, request}) => {
  await openCapture(page, 'http://127.0.0.1:8038');
  await page.locator('#offline-note').fill('Named analyst evidence assessment');
  await page.locator('#offline-save-review').click();
  await expect(page.locator('#message')).toContainText('Analyst key was rejected');
  await page.locator('#offline-analyst-key').fill(ANALYST_KEY);
  await page.locator('#offline-save-review').click();
  await expect(page.locator('#offline-review-history')).toContainText('browser-reviewer');
  await expect(page.locator('#offline-analyst-key')).toHaveValue('');
  const loaded = await stateFor(request, 'http://127.0.0.1:8038');
  expect(loaded.state.entries[0].actor).toBe('browser-reviewer');
  expect(JSON.stringify(loaded.state)).not.toContain(ANALYST_KEY);
});

test('narrow layout keeps review controls and evidence within the viewport', async ({page}, testInfo) => {
  await page.setViewportSize({width: 390, height: 844});
  await openCapture(page);
  await page.locator('#offline-note').fill('Long evidence reference '.repeat(40));
  await page.locator('#offline-events .event').first().locator('summary').click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.locator('#offline-save-review')).toBeVisible();
  await page.screenshot({path: testInfo.outputPath('offline-narrow.png'), fullPage: true});
});
