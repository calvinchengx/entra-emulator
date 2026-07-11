import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Project GitHub Pages site: https://calvinchengx.github.io/entra-emulator/
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/entra-emulator/',
  integrations: [
    starlight({
      title: 'Entra Emulator',
      description:
        'A local, MSAL-compatible emulator of Microsoft Entra ID (Azure AD) in a single Go binary.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/calvinchengx/entra-emulator' },
      ],
      editLink: {
        baseUrl: 'https://github.com/calvinchengx/entra-emulator/edit/main/docs/',
      },
      sidebar: [{ label: 'Documentation', items: [{ autogenerate: { directory: '.' } }] }],
    }),
  ],
});
