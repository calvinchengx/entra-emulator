// Static server for the witness SPA. Serves app/ plus the UNMODIFIED
// msal-browser UMD bundle straight out of node_modules at /vendor/, so the
// browser runs the real library with no build step or bundler in between.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.APP_PORT || 4400);
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json' };

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
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
