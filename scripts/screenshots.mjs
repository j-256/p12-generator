#!/usr/bin/env node
// Generate the README screenshot of the generator form.
//
// Programmatic rather than hand-captured: the page is the whole tool (no chrome
// to crop), the filled-in state is scripted so it never drifts, and
// deviceScaleFactor 2 keeps the form type crisp.
//
// The tool is a static browser app (HTML + CSS + a webpack bundle in static/).
// The screenshot shows the form filled out and ready to generate -- it does NOT
// run a generation, so no real certificate files or secrets are involved. Every
// value entered is an obvious placeholder.
//
// The page is served by a tiny static file server over the repo root, the same
// directory webpack-dev-server serves, so the built static/libraries.js loads.
// Requires a build first: `npm run build`.
//
// Usage:  node scripts/screenshots.mjs [outDir]
// Default outDir is docs/.

import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { extname, join, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const OUT = process.argv[2] || join(ROOT, 'docs');

// Two side-by-side panels; this width shows both without wrapping, and the form
// is short enough that the viewport height captures it whole.
const VIEWPORT = { width: 1280, height: 900 };

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.json': 'application/json',
};

// Fabricated, obviously-fake form values. Nothing here is a real credential; the
// export password is a demo string, not the (real-looking) placeholder in the page.
const FIELDS = {
  hostname: 'cert.staging.store.acme.demandware.net',
  years: '2',
  country: 'US',
  state: 'California',
  locality: 'San Francisco',
  organization: 'Acme Commerce',
  orgUnit: 'Platform Engineering',
  email: 'deploy@acme.example',
  exportPassword: 'demo-export-passphrase',
};

function startStaticServer() {
  const server = createServer((req, res) => {
    // Strip query, prevent path traversal, default to index.html.
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    const rel = normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^(\.\.[/\\])+/, '');
    const filePath = join(ROOT, rel);
    if (!filePath.startsWith(ROOT) || !existsSync(filePath)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    try {
      const body = readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(500);
      res.end('error');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

async function main() {
  if (!existsSync(join(ROOT, 'static', 'libraries.js'))) {
    throw new Error('static/libraries.js not found -- run `npm run build` before capturing screenshots.');
  }
  mkdirSync(OUT, { recursive: true });

  const { server, port } = await startStaticServer();
  const BASE = `http://127.0.0.1:${port}`;

  try {
    const browser = await chromium.launch();
    const context = await browser.newContext({
      viewport: VIEWPORT,
      deviceScaleFactor: 2, // retina: keeps the form labels and inputs sharp
    });
    const page = await context.newPage();

    await page.goto(BASE, { waitUntil: 'networkidle' });
    await page.waitForSelector('#certForm');

    // Fill every text field with its fabricated value. The file input is left
    // empty on purpose: the shot is the form ready to run, not a generation.
    for (const [id, value] of Object.entries(FIELDS)) {
      await page.fill(`#${id}`, value);
    }
    // Blur so no field shows a focus ring, and let layout settle.
    await page.evaluate(() => document.activeElement?.blur());
    // The console-log <pre> renders as an empty dark strip until a generation
    // runs; hide it so the ready-to-run form isn't trailed by a black bar.
    await page.evaluate(() => {
      const log = document.querySelector('#console-log');
      if (log) log.style.display = 'none';
    });
    await page.waitForTimeout(200);

    console.log('capturing into', OUT);
    // Clip to the header + form so the shot is exactly the tool, no page margin
    // below it. The form is the last visible block once the console strip is gone.
    const clip = await page.evaluate(() => {
      const rect = document.querySelector('#certForm').getBoundingClientRect();
      return { x: 0, y: 0, width: document.documentElement.clientWidth, height: Math.ceil(rect.bottom + 24) };
    });
    await page.screenshot({ path: join(OUT, 'form.png'), clip });
    console.log('  wrote form.png');

    await browser.close();
  } finally {
    server.close();
  }
  console.log('done');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
