# Move the site to a custom domain

Everything that prints a documentation URL — the binary, the npm manifest, the
generated pages, `robots.txt`, `sitemap.xml`, `llms.txt` — reads one file.

```bash
echo -n 'https://owlwarden.dev' > site.url
pnpm site:build
pnpm site:check
```

`site.url` holds the origin, with no trailing slash and no newline. `pnpm
site:check` fails when anything disagrees with it, which is the point: a
half-migrated site is worse than either state, because a canonical tag pointing
at a URL that 301s to a different one tells a search engine you are not sure
which page is real.

## Before you flip it

The switch is one line. The migration is not, and doing it in this order is
what keeps the old URLs working.

1. **Own the domain, and point it at the host.** For GitHub Pages that is four
   `A` records for the apex and a `CNAME` for `www`. Confirm both resolve
   before continuing — a canonical tag pointing at a domain that does not
   answer is worse than no canonical tag.
2. **Add the domain in the repository's Pages settings**, and wait for the
   certificate. Then turn on *Enforce HTTPS*. A mixed-scheme site duplicates
   every page.
3. **Flip `site.url`** and rebuild. Commit the regenerated site.
4. **Keep the old paths alive.** GitHub Pages redirects `<user>.github.io/<repo>`
   to a configured custom domain automatically, and that is the 301 the
   migration needs. Verify one deep path by hand — `/rules/stack-trace-leak/` —
   rather than only the root, because the root working proves less than it
   looks like it does.
5. **Update the repository's About field and `package.json` homepage.** npm
   renders `homepage` as the primary link on the package page, and it is
   frequently the only click a reader gives you.
6. **Tell Search Console.** Add the new property, submit the sitemap, and use
   the change-of-address tool. Impressions move over weeks, not days; a drop in
   the first fortnight is the migration, not a mistake.

## Why the tool's own findings do not link to the site

They point at `RULES.md` in the repository instead, and that is deliberate.

`RULES.md` is generated from the compiled-in rules and checked in CI, so the
anchor for every rule that can produce a finding is guaranteed to exist. A site
page is guaranteed only once the site has been deployed, which is not something
a binary printing a finding can know — and a security report full of dead links
is worse than one with no links at all. A reader who follows a 404 while trying
to understand a finding concludes the tool is abandoned, and they are making a
reasonable inference.

`owlwarden explain <rule-id>` prints the whole write-up with no network at all,
which is the version that always works.

## Going back

`echo -n 'https://suthat.github.io/owlwarden' > site.url`, rebuild, and remove
the custom domain from the Pages settings. Nothing else in the repository knows
the difference.
