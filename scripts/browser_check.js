async page => {
  const base = await page.evaluate(() => location.origin);
  const folder = 'tmp/ui-checks';
  const errors = [];
  const results = {};
  const check = (condition, message) => { if (!condition) throw new Error(message); };
  page.on('pageerror', error => errors.push(String(error)));
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto(base);
  await page.getByRole('button', { name: 'Mixed fault and attack', exact: true }).waitFor();
  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Upload view overflows at ' + width);
    await page.screenshot({ path: folder + '/upload-' + width + '.png', fullPage: true });
  }
  await page.locator('#dropzone').focus();
  await page.keyboard.press('Tab');
  check(await page.locator('#anonymize').evaluate(node => node === document.activeElement), 'Upload keyboard order failed');
  await page.getByRole('button', { name: 'Mixed fault and attack', exact: true }).focus();
  await page.keyboard.press('Enter');
  await page.locator('#report').waitFor({ state: 'visible' });
  check(await page.locator('.incident').count() === 3, 'Mixed sample must produce three incidents');
  check(await page.locator('#diagnosis-title').evaluate(node => node === document.activeElement), 'Diagnosis did not receive focus');
  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Report overflows at ' + width);
    await page.screenshot({ path: folder + '/report-' + width + '.png', fullPage: true });
  }
  await page.getByRole('button', { name: 'Faults (1)', exact: true }).click();
  check(await page.locator('.incident:visible').count() === 1, 'Fault filter failed');
  const destination = await page.locator('.band-attack').first().getAttribute('data-target');
  await page.locator('.band-attack').first().focus();
  await page.keyboard.press('Enter');
  check(await page.locator('#incident-' + destination).isVisible(), 'Timeline did not reveal filtered incident');
  check(await page.getByRole('button', { name: 'All (3)', exact: true }).getAttribute('aria-pressed') === 'true', 'Filter state was not reconciled');
  await page.locator('details.evidence').first().locator('summary').click();
  check(await page.locator('details.evidence[open] tbody tr').count() > 0, 'Evidence table is empty');
  await page.locator('details.verdict-box').first().locator('summary').click();
  check(await page.locator('details.verdict-box').first().getAttribute('open') !== null, 'Verdict reasoning cannot be opened');
  for (const name of ['Download JSON', 'Download report']) {
    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name, exact: true }).click();
    const download = await pending;
    await download.saveAs(folder + '/' + download.suggestedFilename());
    if (name === 'Download report') {
      const standalone = await page.context().newPage();
      const location = (await download.path()) + '.html';
      await download.saveAs(location);
      await standalone.goto('file:///' + location.replace(/\\/g, '/'));
      await standalone.locator('.incident').first().waitFor({ state: 'visible' });
      check(await standalone.locator('.incident').count() === 3, 'Downloaded standalone HTML failed');
      await standalone.close();
    }
  }
  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  check(await page.locator('.spinner').evaluate(node => getComputedStyle(node).animationName) === 'none', 'Reduced motion preference ignored');
  const colors = await page.locator('#download-html').evaluate(node => {
    const style = getComputedStyle(node);
    return [style.color, style.backgroundColor].map(color => color.match(/[\d.]+/g).slice(0, 3).map(Number));
  });
  const luminance = values => values.map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  const levels = colors.map(luminance).sort((first, second) => second - first);
  results.darkButtonContrast = (levels[0] + 0.05) / (levels[1] + 0.05);
  check(results.darkButtonContrast >= 4.5, 'Dark button contrast is insufficient');
  await page.screenshot({ path: folder + '/report-dark.png', fullPage: true });
  await page.getByRole('button', { name: 'New analysis', exact: true }).click();
  await page.getByRole('checkbox').check();
  await page.locator('#file-input').setInputFiles('samples/mixed_fault_and_attack.pcap');
  await page.locator('#report').waitFor({ state: 'visible' });
  check(!(await page.locator('#report').innerText()).includes('192.168.1.'), 'Original addresses remain visible');
  await page.getByRole('button', { name: 'New analysis', exact: true }).click();
  await page.getByRole('checkbox').uncheck();
  await page.evaluate(() => {
    const hex = 'd4c3b2a1020004000000000000000000ffff000001000000';
    const bytes = new Uint8Array(hex.match(/../g).map(pair => parseInt(pair, 16)));
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], 'empty.pcap'));
    const input = document.querySelector('#file-input');
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#report').waitFor({ state: 'visible' });
  check(await page.locator('.grade').innerText() === 'Insufficient data', 'Empty capture was presented as healthy');
  await page.getByRole('button', { name: 'New analysis', exact: true }).click();
  await page.evaluate(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['this is not a capture file at all'], 'invalid.pcap'));
    const input = document.querySelector('#file-input');
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.locator('#error').waitFor({ state: 'visible' });
  check(await page.locator('#error').evaluate(node => node === document.activeElement), 'Error did not receive focus');
  await page.getByRole('button', { name: 'Clean (pcapng)', exact: true }).click();
  await page.locator('#report').waitFor({ state: 'visible' });
  check(await page.locator('.incident').count() === 0, 'Clean pcapng produced incidents');
  const started = await page.request.post(base + '/api/analyze-sample/clean.pcap?background=true');
  check(started.status() === 202, 'Background analysis did not start');
  const job = await started.json();
  await page.request.delete(base + '/api/jobs/' + job.job_id);
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await page.request.get(base + '/api/jobs/' + job.job_id);
    if (response.status() === 404) { results.cancellation = 'released'; break; }
    const status = await response.json();
    if (status.status !== 'running') { results.cancellation = status.status; break; }
    await page.waitForTimeout(100);
  }
  check(results.cancellation === 'cancelled' || results.cancellation === 'released', 'Cancelled worker did not finish cleanup');
  check(errors.length === 0, 'JavaScript page errors: ' + errors.join('; '));
  return { ...results, viewports: [1440, 768, 390], mixedIncidents: 3, downloads: 'JSON and standalone HTML passed', privacy: 'passed', keyboard: 'passed', coverage: 'passed', pageErrors: errors };
}
