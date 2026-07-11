import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// Project GitHub Pages site: https://calvinchengx.github.io/entra-emulator/
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/entra-emulator/',
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
            { slug: '00-quickstart' },
            { slug: '13-installation' },
            { slug: '01-architecture' },
            { slug: '02-configuration' },
            { slug: '08-tls-and-origins' },
          ],
        },
        {
          label: 'Data & tokens',
          items: [{ slug: '03-data-model-and-seed' }, { slug: '04-token-service' }],
        },
        {
          label: 'Protocol surface',
          items: [
            { slug: '05-oidc-endpoints' },
            { slug: '06-graph-api' },
            { slug: '15-scim-provisioning' },
          ],
        },
        {
          label: 'Admin & testing',
          items: [
            { slug: '07-admin-api' },
            { slug: '09-testing' },
            { slug: '14-testing-with-forged-tokens' },
            { slug: '17-passkey-sign-in' },
            { slug: '16-externalized-authorization' },
            { slug: '11-e2e-sdk-matrix' },
          ],
        },
        {
          label: 'Roadmap & future',
          items: [{ slug: '10-roadmap' }, { slug: '12-fabric-companion' }],
        },
      ],
    }),
  ],
});
