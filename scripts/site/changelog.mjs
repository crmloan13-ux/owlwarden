import { esc } from "./layout.mjs";

/**
 * The changelog page and its Atom feed, rendered from `CHANGELOG.md`.
 *
 * # Why a Markdown subset and not a parser
 *
 * The input is one file that this repository writes, in Keep a Changelog
 * format, and the output is one page. A general Markdown parser would be a
 * dependency and a much larger attack surface than the job needs.
 *
 * So this handles the subset the changelog actually uses — headings, lists,
 * paragraphs, fenced code, links, inline code, and bold — and **throws on
 * anything it does not recognise structurally**, rather than silently emitting
 * the raw line. A renderer that degrades quietly is a renderer that ships a
 * page with a stray `|` table in it, and nobody notices for a release.
 *
 * # Why a feed
 *
 * Release pages get indexed and rank for the version number, and a feed is the
 * cheapest way for someone who depends on this to hear about a security release
 * without an account or a mailing list — which is the same argument the rest of
 * the tool makes.
 */

/** One released version, parsed out of the changelog. */
export function parseReleases(markdown) {
  const releases = [];
  let current;

  for (const line of markdown.split("\n")) {
    const heading = /^## \[([^\]]+)\](?:\s+—\s+(\d{4}-\d{2}-\d{2}))?/.exec(line);
    if (heading) {
      current = { version: heading[1], date: heading[2], lines: [] };
      // `[Unreleased]` with nothing under it is noise on a public page.
      releases.push(current);
      continue;
    }
    if (current) current.lines.push(line);
  }

  return releases
    .map((release) => ({ ...release, body: release.lines.join("\n").trim() }))
    .filter((release) => release.body.length > 0);
}

/** Renders the changelog page. */
export function changelogPage(markdown, version) {
  const releases = parseReleases(markdown);
  const sections = releases
    .map(
      (release) => `
<h2 id="${esc(slug(release.version))}">${esc(release.version)}${
        release.date ? ` <span class="chip chip-scope">${esc(release.date)}</span>` : ""
      }</h2>
${renderMarkdown(release.body, 3)}`,
    )
    .join("\n");

  return {
    title: "Changelog — owlwarden",
    heading: "What changed, and why",
    description:
      "Every user-visible change to owlwarden, with the security notes spelled out. Rule ids are " +
      "public API and are never silently renamed.",
    ogType: "website",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Changelog", href: "changelog/" },
    ],
    schema: [
      {
        "@type": "CollectionPage",
        name: "owlwarden changelog",
        description: `Release notes for owlwarden, current version ${version}.`,
      },
    ],
    body: `
<p class="lede">
  <strong>Rule ids are public API.</strong> A rule id, once released, is never
  reused for a different check and never silently renamed — CI configs, inline
  suppressions, and agent rules files all reference them. Renames go through a
  deprecation cycle and are listed under <em>Changed</em>.
</p>

<p>
  <a href="./feed.xml">Atom feed</a> ·
  <a href="https://github.com/suthat/owlwarden/releases" rel="noopener">GitHub releases</a> ·
  <a href="../rules/">the rule catalogue</a>
</p>
${sections}
`,
  };
}

/** The Atom feed, one entry per release. */
export function changelogFeed(markdown, site) {
  const releases = parseReleases(markdown).slice(0, 20);
  const updated = releases[0]?.date ?? new Date().toISOString().slice(0, 10);

  const entries = releases
    .map((release) => {
      const id = `${site}/changelog/#${slug(release.version)}`;
      return `  <entry>
    <title>owlwarden ${xml(release.version)}</title>
    <link href="${xml(id)}"/>
    <id>${xml(id)}</id>
    <updated>${xml(release.date ?? updated)}T00:00:00Z</updated>
    <content type="html">${xml(renderMarkdown(release.body, 3))}</content>
  </entry>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>owlwarden releases</title>
  <subtitle>Offline security scanner for Node web apps and AI coding agents.</subtitle>
  <link href="${xml(`${site}/changelog/feed.xml`)}" rel="self"/>
  <link href="${xml(`${site}/changelog/`)}"/>
  <id>${xml(`${site}/changelog/`)}</id>
  <updated>${xml(updated)}T00:00:00Z</updated>
${entries}
</feed>
`;
}

// ---------------------------------------------------------------------------

function slug(version) {
  return version.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function xml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/**
 * Renders the Markdown subset the changelog uses.
 *
 * @param {string} markdown
 * @param {number} baseLevel Heading level for a `###` in the source.
 */
export function renderMarkdown(markdown, baseLevel) {
  const out = [];
  const lines = markdown.split("\n");
  let list = null;
  let paragraph = [];
  let fence = null;

  const closeParagraph = () => {
    if (paragraph.length > 0) {
      out.push(`<p>${inline(paragraph.join(" "))}</p>`);
      paragraph = [];
    }
  };
  const closeList = () => {
    if (list) {
      out.push(`<ul>\n${list.map((item) => `  <li>${inline(item)}</li>`).join("\n")}\n</ul>`);
      list = null;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();

    if (fence !== null) {
      if (line.trimStart().startsWith("```")) {
        out.push(
          `<pre class="code"><code class="language-${esc(fence.language || "text")}">${esc(
            fence.body.join("\n"),
          )}</code></pre>`,
        );
        fence = null;
      } else {
        fence.body.push(raw);
      }
      continue;
    }

    if (line.trimStart().startsWith("```")) {
      closeParagraph();
      closeList();
      fence = { language: line.trim().slice(3).trim(), body: [] };
      continue;
    }

    if (line.trim() === "") {
      closeParagraph();
      closeList();
      continue;
    }

    const heading = /^(#{3,6})\s+(.*)$/.exec(line);
    if (heading) {
      closeParagraph();
      closeList();
      const level = Math.min(6, baseLevel + heading[1].length - 3);
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      continue;
    }

    const item = /^\s*[-*]\s+(.*)$/.exec(line);
    if (item) {
      closeParagraph();
      list ??= [];
      list.push(item[1]);
      continue;
    }

    // A continuation of the previous list item, which the changelog uses for
    // wrapped bullets.
    if (list && /^\s{2,}\S/.test(raw)) {
      list[list.length - 1] += ` ${line.trim()}`;
      continue;
    }

    if (/^[|>]/.test(line.trim())) {
      throw new Error(
        `the changelog renderer does not handle this line, and will not guess:\n  ${line}`,
      );
    }

    closeList();
    paragraph.push(line.trim());
  }

  if (fence !== null) throw new Error("unterminated code fence in CHANGELOG.md");
  closeParagraph();
  closeList();
  return out.join("\n");
}

/** Inline Markdown: links, code spans, bold, emphasis. */
function inline(text) {
  let out = esc(text);
  // Code first, so a link inside a code span is not turned into an anchor.
  out = out.replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`);
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
    const url = /^https?:\/\//.test(href)
      ? href
      : // A relative link in the changelog points into the repository, and this
        // page is not in the repository.
        `https://github.com/suthat/owlwarden/blob/main/${href.replace(/^\.\//, "")}`;
    const external = !url.startsWith("https://github.com/suthat/owlwarden");
    return `<a href="${url}"${external ? ' rel="noopener"' : ""}>${label}</a>`;
  });
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[\s(])\*([^*]+)\*/g, "$1<em>$2</em>");
  return out;
}
