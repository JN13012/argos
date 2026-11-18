/* Fixed anonymous browser driver. No page-supplied code runs in Node. */
'use strict';
const fs = require('node:fs');
const net = require('node:net');
const { chromium } = require('/argos-playwright');

const relaySockets = new Set();

function exchange(request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection('/argos-relay.sock');
    relaySockets.add(socket);
    socket.on('close', () => relaySockets.delete(socket));
    let data = Buffer.alloc(0);
    socket.setTimeout(12000, () => socket.destroy(new Error('relay timeout')));
    socket.on('connect', () => socket.end(JSON.stringify(request) + '\n'));
    socket.on('error', reject);
    socket.on('data', chunk => {
      if (data.length + chunk.length > 800000) {
        socket.destroy(new Error('relay limit'));
      } else data = Buffer.concat([data, chunk]);
    });
    socket.on('end', () => {
      try { resolve(JSON.parse(data.toString('utf8'))); } catch (error) { reject(error); }
    });
  });
}

(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const browser = await chromium.launch({
    executablePath: '/argos-engine/chrome-headless-shell',
    chromiumSandbox: false, // Outer bwrap namespaces/cgroups enforce confinement.
    headless: true,
    timeout: 8000,
    args: ['--disable-dev-shm-usage', '--disable-gpu', '--no-zygote'],
    env: { HOME: '/work', PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
  });
  try {
    const context = await browser.newContext({
      serviceWorkers: 'block', acceptDownloads: false,
      permissions: [], javaScriptEnabled: true,
    });
    let blockedWebsockets = 0;
    let limited = false;
    let requests = 0;
    let queue = Promise.resolve();
    await context.routeWebSocket('**/*', ws => { blockedWebsockets++; ws.close(); });
    if (!input.redirects) await context.route('**/*', route => {
      // Single outstanding relay operation, regardless of page concurrency.
      queue = queue.then(async () => {
        try {
          requests++;
          if (requests > input.max_requests) { limited = true; return await route.abort(); }
          const req = route.request();
          const response = await exchange({
            url: req.url(), method: req.method(), resource: req.resourceType(),
          });
          if (response.blocked) { limited = true; return await route.abort(); }
          await route.fulfill({
            status: response.status, headers: Object.fromEntries(response.headers),
            body: Buffer.from(response.body, 'base64'),
          });
        } catch { limited = true; await route.abort().catch(() => {}); }
      });
      return queue;
    });
    const page = await context.newPage();
    let unsupported = false;
    let stopFetch = () => {};
    const documents = new Set();
    if (input.redirects) {
      // One CDP Fetch session owns every hop. Never continue into Chrome's network.
      const cdp = await context.newCDPSession(page);
      const observer = await browser.newBrowserCDPSession();
      const own = (await cdp.send('Target.getTargetInfo')).targetInfo;
      function blockTarget() {
        unsupported = true; limited = true;
        for (const socket of relaySockets) socket.destroy(new Error('browser request abandoned'));
        context.close().catch(() => {});
      }
      stopFetch = blockTarget;
      observer.on('Target.targetCreated', ({ targetInfo }) => {
        if (targetInfo.browserContextId === own.browserContextId &&
            targetInfo.targetId !== own.targetId &&
            ['page', 'iframe', 'worker', 'shared_worker', 'service_worker'].includes(targetInfo.type)) {
          blockTarget();
        }
      });
      page.on('worker', blockTarget);
      await observer.send('Target.setDiscoverTargets', { discover: true });
      await cdp.send('Network.enable');
      await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
      await cdp.send('Network.setBypassServiceWorker', { bypass: true });
      const ids = new Map();
      cdp.on('Fetch.requestPaused', event => {
        const resourceId = ++requests;
        const parent = event.redirectedRequestId ? ids.get(event.redirectedRequestId) : null;
        if (resourceId <= input.max_requests) ids.set(event.requestId, resourceId);
        queue = queue.then(async () => {
          const abort = () => cdp.send('Fetch.failRequest', {
            requestId: event.requestId, errorReason: 'BlockedByClient',
          }).catch(() => {});
          try {
            if (unsupported || resourceId > input.max_requests || parent === undefined) {
              limited = true; return await abort();
            }
            const types = { Document: 'document', Stylesheet: 'stylesheet', Image: 'image',
              Media: 'media', Font: 'font', Script: 'script', TextTrack: 'texttrack',
              XHR: 'xhr', Fetch: 'fetch', EventSource: 'eventsource', Manifest: 'manifest' };
            const response = await exchange({
              url: event.request.url, method: event.request.method,
              resource: types[event.resourceType] || 'other',
              resource_id: resourceId, redirected_from: parent,
            });
            if (response.blocked) { limited = true; return await abort(); }
            await cdp.send('Fetch.fulfillRequest', {
              requestId: event.requestId, responseCode: response.status,
              responseHeaders: response.headers.map(([name, value]) => ({ name, value })),
              body: response.body,
            });
            if (event.resourceType === 'Document' && ![301,302,303,307,308].includes(response.status)) {
              documents.add(event.request.url.split('#')[0]);
            }
          } catch { limited = true; await abort(); }
        });
      });
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] });
    }
    context.on('page', popup => { if (popup !== page) popup.close().catch(() => {}); });
    page.on('dialog', dialog => dialog.dismiss().catch(() => {}));
    page.on('download', download => download.cancel().catch(() => {}));
    let state = 'observed';
    try {
      await page.goto(input.url, { waitUntil: 'domcontentloaded', timeout: 12000 });
      await page.waitForTimeout(1000);
      // The host may need several seconds per isolated exchange. Drain the
      // bounded relay queue before capturing a DOM produced by fetch callbacks.
      for (let i = 0; i < input.max_requests; i++) {
        const current = queue;
        await current;
        await page.waitForTimeout(100);
        if (current === queue) break;
      }
    } catch { state = 'partial'; if (input.redirects) stopFetch(); }
    const snapshot = await page.evaluate(maxLinks => {
      const links = [];
      const seen = new Set();
      let bytes = 0;
      let limited = false;
      // Bound exported DOM observations; no full DOM serialization.
      const elements = document.querySelectorAll('a[href],area[href]');
      for (let i = 0; i < Math.min(elements.length, 1024); i++) {
        const href = elements[i].href;
        if (!href || seen.has(href)) continue;
        if (href.length > 8192 || links.length >= maxLinks || bytes + href.length > 65536) {
          limited = true; break;
        }
        seen.add(href); links.push(href); bytes += href.length;
      }
      return { links, limited: limited || elements.length > 1024 };
    }, input.max_links || 128).catch(() => ({ links: [], limited: true }));
    let finalUrl = input.redirects && !unsupported ? page.url() : null;
    if (input.redirects && finalUrl !== null && (Buffer.byteLength(finalUrl, 'utf8') > 8192 ||
        !documents.has(finalUrl.split('#')[0]))) {
      finalUrl = null; limited = true;
    }
    await context.close();
    await queue;
    const output = {
      version: input.redirects ? 'argos-browser-v2' : 'argos-browser-v1', state, links: snapshot.links,
      browser_version: browser.version(),
      limited: limited || snapshot.limited, blocked_websockets: blockedWebsockets,
    };
    if (input.redirects) output.final_url = finalUrl;
    process.stdout.write(JSON.stringify(output));
  } finally { await browser.close(); }
})().catch(() => { process.stderr.write('Browser execution failed\n'); process.exitCode = 1; });
