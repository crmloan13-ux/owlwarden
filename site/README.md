# site/

Generated. Run `pnpm site:build`; the only file in here that is not generated is
`favicon.png`, which is the illustrated mark used as the Apple touch icon.

The generator is `scripts/build-site.mjs`, and it reads three things:

- **`site.url`** at the repository root — the origin, and the only place it
  exists. See [docs/how-to/custom-domain.md](../docs/how-to/custom-domain.md).
- **the engine**, for the rule catalogue, the coverage tables, and every rule's
  remediation. The same source that generates `RULES.md`.
- **the fixtures**, which it scans to harvest a real vulnerable example for each
  (rule, framework) and (rule, agent host) cell.

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

`favicon.svg` is generated and is drawn for the size it is actually seen at.
The illustrated owl it replaced is a good drawing and is unreadable in a browser
tab: at 16 pixels the tufts, the eye rings, and the registration marks collapse
into a smudge. Four shapes, maximum contrast, and the three features that make a
silhouette read as an owl — two large adjacent eyes, ear tufts attached to a
head, and a beak between them. It keeps the severity red the reporter uses for
`high`, so the tab, the page, and the terminal are one object.

`favicon.png` stays as the `apple-touch-icon`, where 192×192 is the size it is
actually rendered at and the illustration's detail earns its place.

## The social card

`og.svg` is generated; `og.png` is rasterised from it and committed.

```bash
pnpm og:build     # writes og.svg, and og.png on macOS
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
