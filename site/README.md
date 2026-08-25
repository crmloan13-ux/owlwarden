# site/

Generated. Run `pnpm site:build`; do not edit anything in here by hand except
`favicon.png` and `og.jpg`.

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

## Per-page social images

There is one `og.jpg` for the whole site. Per-page images rendering the actual
finding would be better — it is the most recognisable artefact this project has
— but producing them means rasterising 200 images at build time, which needs a
headless browser or an image library. Neither is worth adding to a repository
whose dependency posture is a feature. Faking it with an SVG would not work
either: the platforms that matter do not render SVG in a social card.
