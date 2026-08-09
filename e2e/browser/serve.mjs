// Static server for the witness SPA. Serves app/ plus the UNMODIFIED
// msal-browser UMD bundle straight out of node_modules at /vendor/, so the
// browser runs the real library with no build step or bundler in between.
//
// It also plays the part of a relying party for front-channel logout: the
// emulator renders a hidden iframe per signed-into RP, and /frontchannel-logout
// records the hits so a test can assert the browser really fetched them. That
// is the half a Go test cannot reach — server-side it can only check that the
// HTML contains an iframe, never that a browser acted on it.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.APP_PORT || 4400);
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json' };

// Front-channel logout callbacks observed, in arrival order.
let logoutHits = [];

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // The RP's front-channel logout endpoint. The spec sends iss and sid as
  // query parameters; both are recorded so a test can assert they arrived
  // rather than merely that something was fetched.
  if (url.pathname === '/frontchannel-logout') {
    logoutHits.push({
      iss: url.searchParams.get('iss'),
      sid: url.searchParams.get('sid'),
    });
    res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
    res.end('<!doctype html><title>logged out</title>');
    return;
  }

  // Test-side inspection of what arrived. DELETE resets between tests so one
  // test never reads another's hits.
  if (url.pathname === '/logout-hits') {
    if (req.method === 'DELETE') {
      logoutHits = [];
      res.writeHead(204).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(logoutHits));
    return;
  }

  let file;
  if (url.pathname.startsWith('/vendor/')) {
    file = join(here, 'node_modules/@azure/msal-browser/lib', url.pathname.slice('/vendor/'.length));
  } else {
    file = join(here, 'app', url.pathname === '/' ? 'index.html' : url.pathname);
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(PORT, () => console.log(`witness app on http://localhost:${PORT}`));
