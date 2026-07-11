import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// Project GitHub Pages site: https://calvinchengx.github.io/entra-emulator/
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/entra-emulator/',
  // Docs were renumbered into reading order; keep the old published URLs alive.
  redirects: {
    '/00-quickstart/': '/entra-emulator/01-quickstart/',
    '/13-installation/': '/entra-emulator/02-installation/',
    '/01-architecture/': '/entra-emulator/03-architecture/',
    '/02-configuration/': '/entra-emulator/04-configuration/',
    '/08-tls-and-origins/': '/entra-emulator/05-tls-and-origins/',
    '/03-data-model-and-seed/': '/entra-emulator/06-data-model-and-seed/',
    '/04-token-service/': '/entra-emulator/07-token-service/',
    '/05-oidc-endpoints/': '/entra-emulator/08-oidc-endpoints/',
    '/06-graph-api/': '/entra-emulator/09-graph-api/',
    '/15-scim-provisioning/': '/entra-emulator/10-scim-provisioning/',
    '/07-admin-api/': '/entra-emulator/11-admin-api/',
    '/09-testing/': '/entra-emulator/12-testing/',
    '/14-testing-with-forged-tokens/': '/entra-emulator/13-testing-with-forged-tokens/',
    '/17-passkey-sign-in/': '/entra-emulator/14-passkey-sign-in/',
    '/16-externalized-authorization/': '/entra-emulator/15-externalized-authorization/',
    '/11-e2e-sdk-matrix/': '/entra-emulator/16-e2e-sdk-matrix/',
    '/10-roadmap/': '/entra-emulator/17-roadmap/',
    '/12-fabric-companion/': '/entra-emulator/18-fabric-companion/',
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
            { slug: 'index' },
            { slug: '01-quickstart' },
            { slug: '02-installation' },
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
          ],
        },
        {
          label: 'Roadmap & future',
          items: [{ slug: '17-roadmap' }, { slug: '18-fabric-companion' }],
        },
      ],
    }),
  ],
});
