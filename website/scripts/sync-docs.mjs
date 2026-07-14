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
import { collectParity, writeParityHistory, parityManifest } from './parity-versions.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = join(here, '..', '..');
const DOCS_SRC = join(REPO, 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
export const BASE = '/entra-emulator/';

// Parity version data (release tags + the live map), collected once. `version`
// is e.g. "v0.2.2" on a tag, otherwise "latest-<short sha>".
const PARITY = collectParity(REPO);
const IS_RELEASE = /^v\d+\.\d+\.\d+$/.test(PARITY.version);
// The parity map is the one doc without a reading-order number: it is a living
// reference rather than a chapter, and its URL is just /parity/.
const PARITY_RE = /(^|[/-])parity\.md$/;
// Docs are `NN-name.md` chapters, plus the un-numbered parity map.
const DOC_RE = /^(\d{2}-.*|parity)\.md$/;

// Rewrite `](./|docs/ NN-slug.md#anchor)` → `](/entra-emulator/NN-slug/#anchor)`.
const LINK_RE = /\]\((?:\.\/|docs\/)?(\d{2}-[a-z0-9-]+|parity)\.md(#[^)]*)?\)/g;
function rewriteLinks(md) {
  return md.replace(LINK_RE, (_m, slug, anchor) => `](${BASE}${slug}/${anchor ?? ''})`);
}

// "07 — Admin REST API & portal" → "Admin REST API & portal".
function cleanTitle(h1) {
  return h1.replace(/^\d+[a-z]?\s*[—:-]\s*/i, '').trim();
}

function yamlEscape(s) {
  // Escape backslashes first, then quotes — otherwise a literal backslash in a
  // title would leak through and corrupt the double-quoted YAML scalar.
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// Strip the leading H1 (Starlight renders the frontmatter title) and rewrite
// intra-doc links. Shared with the parity snapshot generator so historical
// snapshots convert identically.
function convertBody(raw) {
  const lines = raw.split('\n');
  const h1Index = lines.findIndex((l) => /^#\s+/.test(l));
  if (h1Index >= 0) {
    lines.splice(h1Index, lines[h1Index + 1]?.trim() === '' ? 2 : 1);
  }
  return rewriteLinks(lines.join('\n').replace(/^\n+/, ''));
}

// The context line at the top of the live parity map. Switching versions is the
// top-nav picker's job (src/components/ParityVersionPicker.astro) — this just
// says which version you're reading.
function parityStamp() {
  const what = IS_RELEASE
    ? `release **${PARITY.version}**`
    : `**${PARITY.version}** (the live tip of \`main\`)`;
  return (
    `_Parity map as of ${what} — tracked by git release tags. ` +
    `See the [version history](${BASE}parity-history/) and [parity changelog](${BASE}parity-history/changelog/)._\n\n`
  );
}

function convert(name) {
  const raw = readFileSync(join(DOCS_SRC, name), 'utf8');
  const h1 = raw.split('\n').find((l) => /^#\s+/.test(l));
  const title = h1 ? cleanTitle(h1.replace(/^#\s+/, '')) : name.replace(/\.md$/, '');
  let body = convertBody(raw);
  if (PARITY_RE.test(name)) body = parityStamp() + body;
  // Point "Edit this page" at the real source in /docs (the generated copy
  // under src/content/docs/ is git-ignored), not Starlight's default path.
  const editUrl = `https://github.com/calvinchengx/entra-emulator/edit/main/docs/${name}`;
  const frontmatter = `---\ntitle: ${yamlEscape(title)}\neditUrl: ${yamlEscape(editUrl)}\n---\n\n`;
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
      `- [Architecture](03-architecture.md) — how the pieces fit together\n` +
      `- [Configuration](04-configuration.md) — environment and origins\n` +
      `- [OIDC endpoints](08-oidc-endpoints.md) — discovery, authorize, token, device code\n` +
      `- [Admin REST API](11-admin-api.md) — the portal's control surface\n` +
      `- [Roadmap](17-roadmap.md) — delivered features and what's out of scope\n`,
  );
  // The landing page is synthesized here (no /docs source), so it has no
  // "Edit this page" target.
  const frontmatter =
    `---\ntitle: Entra Emulator\ndescription: A local, MSAL-compatible emulator of Microsoft Entra ID in a single Go binary.\neditUrl: false\n---\n\n`;
  writeFileSync(join(OUT, 'index.md'), frontmatter + body);
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const names = readdirSync(DOCS_SRC).filter((n) => DOC_RE.test(n)).sort();
for (const name of names) {
  writeFileSync(join(OUT, name), convert(name));
}
writeIndex();
const info = writeParityHistory(OUT, PARITY, { convertBody });
// The top-nav picker is an Astro component and can't shell out to git, so hand
// it the same points as a build-time manifest.
const DATA = join(here, '..', 'src', 'data');
mkdirSync(DATA, { recursive: true });
writeFileSync(join(DATA, 'parity-versions.json'), JSON.stringify(parityManifest(PARITY), null, 2) + '\n');
console.log(
  `sync-docs: wrote ${names.length} docs + index to src/content/docs/ ` +
    `(parity ${info.version}; ${info.snapshots.length} tagged snapshot(s))`,
);
