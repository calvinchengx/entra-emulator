import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// Project GitHub Pages site: https://calvinchengx.github.io/entra-emulator/
//
// THE DOCS LIVE UNDER /docs/, with the hand-written landing page at the root.
// That is the family's shape (data-agent-service, data-agent-voice, apim,
// snowflake, emulators). It moved 61 published routes, and NONE of them broke:
// scripts/assemble_site.py writes a redirect stub at every old path and holds
// itself to website/published-routes.txt, the list captured from the build
// immediately before the move.
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/entra-emulator/docs/',
  // Docs were renumbered into reading order; keep the old published URLs alive.
  // These serve UNDER the base, so they cover an old slug typed beneath /docs/.
  // The root-level old URLs are stubs from assemble_site.py: an Astro redirect
  // key is emitted under the base and cannot answer a path above it.
  redirects: {
    '/00-quickstart/': '/entra-emulator/docs/01-quickstart/',
    '/13-installation/': '/entra-emulator/docs/02-installation/',
    '/01-architecture/': '/entra-emulator/docs/03-architecture/',
    '/02-configuration/': '/entra-emulator/docs/04-configuration/',
    '/08-tls-and-origins/': '/entra-emulator/docs/05-tls-and-origins/',
    '/03-data-model-and-seed/': '/entra-emulator/docs/06-data-model-and-seed/',
    '/04-token-service/': '/entra-emulator/docs/07-token-service/',
    '/05-oidc-endpoints/': '/entra-emulator/docs/08-oidc-endpoints/',
    '/06-graph-api/': '/entra-emulator/docs/09-graph-api/',
    '/15-scim-provisioning/': '/entra-emulator/docs/10-scim-provisioning/',
    '/07-admin-api/': '/entra-emulator/docs/11-admin-api/',
    '/09-testing/': '/entra-emulator/docs/12-testing/',
    '/14-testing-with-forged-tokens/': '/entra-emulator/docs/13-testing-with-forged-tokens/',
    '/17-passkey-sign-in/': '/entra-emulator/docs/14-passkey-sign-in/',
    '/16-externalized-authorization/': '/entra-emulator/docs/15-externalized-authorization/',
    '/11-e2e-sdk-matrix/': '/entra-emulator/docs/16-e2e-sdk-matrix/',
    '/10-roadmap/': '/entra-emulator/docs/17-roadmap/',
    '/12-fabric-companion/': '/entra-emulator/docs/18-fabric-companion/',
  },
  // remarkMermaid turns ```mermaid fences into <pre class="mermaid"> before
  // Expressive Code sees them; src/components/Head.astro renders them client-side.
  markdown: {
    remarkPlugins: [remarkMermaid],
  },
  integrations: [
    starlight({
      title: 'Entra Emulator',
      components: {
        Head: './src/components/Head.astro',
        // Top nav: the parity version picker, rendered beside the search box.
        // Search occupies the header's un-gated middle slot, so the picker stays
        // in the top bar at every width (the right-group holding ThemeSelect is
        // `sl-hidden md:sl-flex`, so a picker there vanishes on mobile). The
        // picker shows itself only on the parity pages.
        Search: './src/components/Search.astro',
      },
      description:
        'A local, MSAL-compatible emulator of Microsoft Entra ID (Azure AD) in a single Go binary.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/calvinchengx/entra-emulator' },
      ],
      editLink: {
        baseUrl: 'https://github.com/calvinchengx/entra-emulator/edit/main/docs/',
      },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            // The docs' front door. It was slug 'overview' while Starlight
            // was based at the root and index.html belonged to the landing
            // page; under /docs/ there is no collision and it is the index
            // again. Starlight names the index slug with an empty string.
            { slug: '' },
            { slug: '01-quickstart' },
            { slug: '02-installation' },
            { slug: '21-platform-setup' },
            { slug: '03-architecture' },
            { slug: '04-configuration' },
            { slug: '05-tls-and-origins' },
          ],
        },
        {
          label: 'Data & tokens',
          items: [{ slug: '06-data-model-and-seed' }, { slug: '07-token-service' }],
        },
        {
          label: 'Protocol surface',
          items: [
            { slug: '08-oidc-endpoints' },
            { slug: '09-graph-api' },
            { slug: '10-scim-provisioning' },
          ],
        },
        {
          label: 'Admin & testing',
          items: [
            { slug: '11-admin-api' },
            { slug: '12-testing' },
            { slug: '13-testing-with-forged-tokens' },
            { slug: '14-passkey-sign-in' },
            { slug: '15-externalized-authorization' },
            { slug: '16-e2e-sdk-matrix' },
            { slug: '19-golden-reference-parity' },
            { slug: '20-stateful-directory' },
          ],
        },
        {
          label: 'Roadmap & future',
          items: [
            { slug: '17-roadmap' },
            { slug: '18-fabric-companion' },
            { slug: '22-arm-companion' },
          ],
        },
        {
          // The live map first, then the pages generated by
          // scripts/parity-versions.mjs from the git release tags. The history
          // index lists every per-version snapshot, so it doubles as the version
          // browser (this Starlight's sidebar has no autogenerate). The map's own
          // title is long; in this group it just needs to say Parity.
          label: 'Parity',
          items: [
            { slug: 'parity', label: 'Parity' },
            { slug: 'parity-history' },
            { slug: 'parity-history/changelog' },
          ],
        },
      ],
    }),
  ],
});
