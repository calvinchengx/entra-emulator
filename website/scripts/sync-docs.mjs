// Generates Starlight content from the canonical Markdown in /docs, keeping
// /docs as the single source of truth (its files stay pristine and their
// GitHub-relative links keep working). Run automatically before dev/build.
//
// For each docs/NN-name.md it: derives the title from the leading H1, injects
// Starlight frontmatter, drops the duplicate H1, and rewrites intra-doc
// `NN-name.md` links to site routes under the configured base.
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const DOCS_SRC = join(here, '..', '..', 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
export const BASE = '/entra-emulator/';

// Rewrite `](./|docs/ NN-slug.md#anchor)` → `](/entra-emulator/NN-slug/#anchor)`.
const LINK_RE = /\]\((?:\.\/|docs\/)?(\d{2}-[a-z0-9-]+)\.md(#[^)]*)?\)/g;
function rewriteLinks(md) {
  return md.replace(LINK_RE, (_m, slug, anchor) => `](${BASE}${slug}/${anchor ?? ''})`);
}

// "07 — Admin REST API & portal" → "Admin REST API & portal".
function cleanTitle(h1) {
  return h1.replace(/^\d+[a-z]?\s*[—:-]\s*/i, '').trim();
}

function yamlEscape(s) {
  return '"' + s.replace(/"/g, '\\"') + '"';
}

function convert(name) {
  const raw = readFileSync(join(DOCS_SRC, name), 'utf8');
  const lines = raw.split('\n');
  const h1Index = lines.findIndex((l) => /^#\s+/.test(l));
  const title = h1Index >= 0 ? cleanTitle(lines[h1Index].replace(/^#\s+/, '')) : name.replace(/\.md$/, '');
  // Drop the H1 (Starlight renders the frontmatter title) and a trailing blank.
  if (h1Index >= 0) {
    lines.splice(h1Index, lines[h1Index + 1]?.trim() === '' ? 2 : 1);
  }
  const body = rewriteLinks(lines.join('\n').replace(/^\n+/, ''));
  const frontmatter = `---\ntitle: ${yamlEscape(title)}\n---\n\n`;
  return frontmatter + body;
}

function writeIndex() {
  const body = rewriteLinks(
    `Local, MSAL-compatible emulator of Microsoft Entra ID (Azure AD) in a single Go binary — ` +
      `the OIDC/OAuth 2.0 v2.0 endpoints MSAL talks to, a minimal read-only Microsoft Graph, and an ` +
      `unauthenticated admin REST API, so you can develop sign-in, token acquisition, and ` +
      `protected-API calls offline with no cloud tenant.\n\n` +
      `:::caution\nLocal development tool only — intentionally insecure (open admin API, publicly known ` +
      `seeded users/secrets, self-signed TLS, unencrypted signing key). Run it on \`localhost\` only.\n:::\n\n` +
      `## Start here\n\n` +
      `- [Architecture](01-architecture.md) — how the pieces fit together\n` +
      `- [Configuration](02-configuration.md) — environment and origins\n` +
      `- [OIDC endpoints](05-oidc-endpoints.md) — discovery, authorize, token, device code\n` +
      `- [Admin REST API](07-admin-api.md) — the portal's control surface\n` +
      `- [Roadmap](10-roadmap.md) — delivered features and what's out of scope\n`,
  );
  const frontmatter =
    `---\ntitle: Entra Emulator\ndescription: A local, MSAL-compatible emulator of Microsoft Entra ID in a single Go binary.\n---\n\n`;
  writeFileSync(join(OUT, 'index.md'), frontmatter + body);
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const names = readdirSync(DOCS_SRC).filter((n) => /^\d{2}-.*\.md$/.test(n)).sort();
for (const name of names) {
  writeFileSync(join(OUT, name), convert(name));
}
writeIndex();
console.log(`sync-docs: wrote ${names.length} docs + index to src/content/docs/`);
