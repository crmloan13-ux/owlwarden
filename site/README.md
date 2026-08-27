# site/

Generated. Run `pnpm site:build`; do not edit the HTML in this directory. The
PNG brand assets are committed build outputs because browsers and social cards
need raster files, but their source is generated too.

The generator is `scripts/build-site.mjs`, and it reads three things:

- **`site.url`** at the repository root — the origin, and the only place it
  exists. See [docs/how-to/custom-domain.md](../docs/how-to/custom-domain.md).
- **the engine**, for the rule catalogue, the coverage tables, and every rule's
  remediation. The same source that generates `RULES.md`.
- **the fixtures**, which it scans to harvest a real vulnerable example for each
  (rule, framework) and (rule, agent host) cell.

The hand-written layer is split by job rather than by output page:

- `scripts/site/marketing.mjs` owns every product hero, call to action, and
  product visual as structured content;
- `scripts/site/pages.mjs` owns the long-form explanations;
- `scripts/site/layout.mjs` owns the shared HTML and SEO metadata;
- `scripts/site/styles.mjs` owns the visual system.

That means a positioning or design change is one source edit even though GitHub
Pages receives a pre-rendered file for every indexable URL. The HTML count is a
deployment detail, not an authoring model; pre-rendering keeps each rule URL
fast, crawlable, and useful without shipping client JavaScript.

That last one is the reason a few hundred pages can exist without any of them
being filler. Every snippet on the site is a finding the test suite already
asserts on. If a rule stops firing, its pages lose their example and the build
says so — rather than the site quietly describing behaviour the tool no longer
has. A cell with no example from its own fixture is not published at all: thin
pages at scale is the one way this tactic backfires.

## Checks

```bash
pnpm site:build          # write site/
pnpm site:check          # is it current, and is it correct?
```

`build-site.mjs --check` answers *is the committed site what the current rules
would generate?* and needs the native addon. `check-site.mjs` answers *is the
committed site correct?* — one `<h1>` per page, a self-referencing canonical, a
description that will not be truncated, valid JSON-LD, no heading-level jumps,
no dead links across the whole graph, and no external host anywhere. It needs
nothing but Node, which is why the Pages workflow can run it.

## What is deliberately absent

No JavaScript ships. No font CDN, no analytics, no tag manager, no third-party
anything — a tool whose entire argument is that it sends nothing anywhere cannot
have a page that makes three external requests before the reader has read a
sentence. `check-site.mjs` refuses any host outside a short allowlist, and any
`<script>` that is not JSON-LD.

## The icons

`favicon.svg` is the source mark, drawn for browser-tab legibility. Its guardian
owl uses short outward feather tufts, one connected facial disc, and an open
centre so the silhouette stays readable at 16 pixels without a nose or beak.
The header, footer, favicon, Apple touch icon, install icons, web manifest, and
social card all use that same geometry and the reporter's severity red.
`pnpm brand:build` rasterises the 180, 192, and 512 pixel variants from a 4x
render on macOS, so curves and diagonal edges stay clean and there is no second
owl illustration to drift away from the product mark.

## The social card

`og.svg` is generated; `og.png` is rasterised from it and committed.

```bash
pnpm brand:build  # writes the social card and all raster icon sizes on macOS
```

Social platforms do not render SVG in a card, so the `og:image` has to be a
raster — and producing one needs a headless browser or an image library, neither
of which belongs in this dependency tree. So the vector source sits next to the
raster and anyone can regenerate the PNG with any tool. `build-og.mjs --raster`
uses Quick Look and `sips`, which ship with macOS.

The card shows a **finding**, not a wordmark on a gradient: the
`.claude/settings.json` hook that runs when anyone opens the folder. It is the
one image that says the whole argument, and nobody else in this category can
put it on a card, because nobody else reads that file.

Per-page cards would be better still and would mean rasterising two hundred
images at build time. That is the trade this repository does not make.
