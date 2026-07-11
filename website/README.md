# Documentation site

The public docs site ([calvinchengx.github.io/entra-emulator](https://calvinchengx.github.io/entra-emulator/)),
built with [Astro Starlight](https://starlight.astro.build/) and published to GitHub Pages
by [`.github/workflows/docs-site.yml`](../.github/workflows/docs-site.yml).

**The source of truth is [`/docs`](../docs).** Those numbered Markdown files stay pristine
(and keep working when browsed on GitHub). A prebuild step,
[`scripts/sync-docs.mjs`](scripts/sync-docs.mjs), copies them into `src/content/docs/`
(git-ignored, regenerated each build), injecting Starlight frontmatter from each file's H1
and rewriting `NN-name.md` cross-links to site routes. **Edit `/docs`, not
`src/content/docs/`.**

## Develop

This repo is a [pnpm](https://pnpm.io) workspace (`pnpm` is enforced — `npm`/`yarn` are
blocked by a `preinstall` guard). From the repo root:

```sh
pnpm install
pnpm docs:dev     # sync + astro dev  → http://localhost:4321/entra-emulator/
pnpm docs:build   # sync + astro build → website/dist/
```

Adding a doc: drop `docs/NN-title.md` with a leading `# H1`; the sidebar orders by the
numeric prefix automatically. Versions are pinned in [`package.json`](package.json) and the
root `pnpm-lock.yaml` for reproducible Pages builds.
