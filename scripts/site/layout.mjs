import { THEME } from "./theme.mjs";

/**
 * The page shell every generated page shares.
 *
 * One function, so a change to the head block reaches ~290 pages rather than
 * one. The parts that vary per page are the parts a search engine reads
 * differently per page: title, description, canonical, JSON-LD, breadcrumbs.
 *
 * # What is deliberately absent
 *
 * No external hosts. No font CDN, no analytics, no tag manager. A tool whose
 * entire argument is that it sends nothing anywhere cannot have a page that
 * makes three third-party requests before the reader has read a sentence — and
 * a `check-site` assertion enforces it, because that is the kind of thing that
 * gets added later "just for a week".
 */

/** Escapes text for an HTML attribute or text node. */
export function esc(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Escapes a string for embedding inside a JSON-LD block. */
function jsonLd(value) {
  // `</script>` inside a JSON string would close the block early; escaping the
  // slash is the standard fix and stays valid JSON.
  return JSON.stringify(value, null, 2).replaceAll("</", "<\\/");
}

/**
 * Problems found while rendering, reported together at the end of the build.
 *
 * Collected rather than thrown, because a build that fails on the first of
 * fourteen makes you run it fourteen times to find out how much work there is.
 */
export const problems = [];

/** The one ordered set of destinations used by every generated page. */
const PRIMARY_NAV_ITEMS = [
  { section: "Rules", label: "Rules", href: "rules/" },
  { section: "Agent config", label: "Agent config", href: "agent-config-security/" },
  { section: "turn", label: "turn", href: "turn/" },
  { section: "vet", label: "vet", href: "vet/" },
  { section: "Offline", label: "Offline", href: "offline/" },
  { section: "Coverage", label: "Coverage", href: "owasp/" },
];

/**
 * A description that will actually render in a result.
 *
 * Google truncates around 155–160 characters. Shorter than ~110 and the snippet
 * looks thin next to competitors; longer than 165 and the end is cut mid-word,
 * which is where the reason to click usually lives.
 */
export function checkDescription(description, where) {
  if (description.length < 110 || description.length > 165) {
    problems.push(
      `${where}: description is ${description.length} chars, aim for 110-165\n    ${description}`,
    );
  }
  return description;
}

/** A title that will not be truncated in a result. */
export function checkTitle(title, where) {
  if (title.length > 62) {
    problems.push(`${where}: title is ${title.length} chars, aim for under 60\n    ${title}`);
  }
  return title;
}

/**
 * Renders one page.
 *
 * @param {object} page
 * @param {string} page.path        Site-relative path, e.g. `rules/ssrf/`.
 * @param {string} page.title       Under 60 chars, brand suffix added here.
 * @param {string} page.description 110-165 chars, written to be clicked.
 * @param {string} page.heading     The single `<h1>`.
 * @param {string} page.body        Rendered HTML for `<main>`.
 * @param {object} [page.hero]      Structured product intro for marketing pages.
 * @param {Array}  page.breadcrumbs `[{ label, href }]`, current page last.
 * @param {Array}  page.schema      JSON-LD objects.
 * @param {string} site             Origin, from `site.url`.
 * @param {string} version          Engine version for the footer.
 * @param {string} assetVersion     Content hash for immutable browser caching.
 */
export function renderPage(page, site, version, assetVersion) {
  const canonical = `${site}/${page.path}`;
  // Directory depth, not path segments: `404.html` sits at the root and needs
  // `./`, while `rules/ssrf/` sits two deep and needs `../../`. Counting
  // segments would give the 404 page a `../` prefix on every link — pointing
  // one level above the site, which is the kind of break nobody clicks until a
  // reader does.
  const segments = page.path.split("/").filter(Boolean);
  const depth = page.path.endsWith("/") || page.path === "" ? segments.length : segments.length - 1;
  // Relative asset paths so the whole site works from a subdirectory *and* from
  // a custom domain without a rebuild of every href.
  const up = depth <= 0 ? "./" : "../".repeat(depth);

  const description = checkDescription(page.description, page.path || "/");
  const title = checkTitle(
    page.title.includes("owlwarden") ? page.title : `${page.title}: owlwarden`,
    page.path || "/",
  );

  const graph = [
    {
      "@type": "WebSite",
      "@id": `${site}/#website`,
      name: "owlwarden",
      url: `${site}/`,
      description: "Local security scanner for Node apps and coding-agent configuration.",
      inLanguage: "en",
    },
    {
      "@type": "BreadcrumbList",
      "@id": `${canonical}#breadcrumbs`,
      itemListElement: page.breadcrumbs.map((crumb, index) => ({
        "@type": "ListItem",
        position: index + 1,
        name: crumb.label,
        item: crumb.href.startsWith("http") ? crumb.href : `${site}/${crumb.href}`,
      })),
    },
    ...(page.schema ?? []),
  ];
  const robots = page.path === "404.html"
    ? "noindex,follow"
    : "index,follow,max-image-preview:large,max-snippet:-1";

  return normalizeSiteCopy(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">

<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(canonical)}">
<meta name="robots" content="${robots}">
<meta name="theme-color" content="${THEME.paper}">

<meta property="og:type" content="${page.ogType ?? "article"}">
<meta property="og:locale" content="en_US">
<meta property="og:site_name" content="owlwarden">
<meta property="og:title" content="${esc(page.heading)}">
<meta property="og:description" content="${esc(page.ogDescription ?? description)}">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:image" content="${site}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="An owlwarden finding: a SessionStart hook in .claude/settings.json that runs a command when the workspace is opened">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(page.heading)}">
<meta name="twitter:description" content="${esc(page.ogDescription ?? description)}">
<meta name="twitter:image" content="${site}/og.png">
<meta name="twitter:image:alt" content="An owlwarden scan showing the exact vulnerable line and its fix">

<link rel="icon" type="image/svg+xml" href="${up}favicon.svg">
<link rel="alternate icon" type="image/png" sizes="192x192" href="${up}favicon.png">
<link rel="apple-touch-icon" sizes="180x180" href="${up}apple-touch-icon.png">
<link rel="manifest" href="${up}manifest.webmanifest">
<link rel="alternate" type="application/atom+xml" title="owlwarden releases" href="${site}/changelog/feed.xml">
<link rel="stylesheet" href="${up}styles.css?v=${esc(assetVersion)}">

<script type="application/ld+json">
${jsonLd({ "@context": "https://schema.org", "@graph": graph })}
</script>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>

<header class="site-header">
  <a class="wordmark" href="${up}">
    <img src="${up}favicon.svg" width="32" height="32" alt="">
    <span>owlwarden</span>
  </a>
  <nav aria-label="Primary">
${renderPrimaryNavigation(page.path, up)}
    <a class="nav-cta" href="https://github.com/suthat/owlwarden" rel="noopener">GitHub <span aria-hidden="true">↗</span></a>
  </nav>
</header>

<nav class="breadcrumbs" aria-label="Breadcrumb">
  <ol>
${page.breadcrumbs
  .map((crumb, index) => {
    const last = index === page.breadcrumbs.length - 1;
    const href = crumb.href.startsWith("http") ? crumb.href : `${up}${crumb.href}`;
    return last
      ? `    <li aria-current="page">${esc(crumb.label)}</li>`
      : `    <li><a href="${esc(href)}">${esc(crumb.label)}</a></li>`;
  })
  .join("\n")}
  </ol>
</nav>

<main id="main-content" class="${page.hero ? "with-hero" : "article-page"}">
${renderHero(page)}
${page.body}
</main>

<footer class="site-footer">
  <div class="footer-brand">
    <img src="${up}favicon.svg" width="36" height="36" alt="">
    <p><strong>owlwarden ${esc(version)}</strong><br>Local security checks for Node apps and coding-agent configuration.</p>
  </div>
  <nav aria-label="Footer">
    <a href="${up}turn/">turn</a>
    <a href="${up}rules/">All rules</a>
    <a href="${up}owasp/">OWASP coverage</a>
    <a href="${up}asi/">ASI coverage</a>
    <a href="${up}offline/">Offline</a>
    <a href="${up}ci/">CI</a>
    <a href="${up}mcp/">MCP</a>
    <a href="https://github.com/suthat/owlwarden/blob/main/RULES.md" rel="noopener">RULES.md</a>
    <a href="https://www.npmjs.com/package/owlwarden" rel="noopener">npm</a>
  </nav>
  <p class="licence">No account / no telemetry / MIT OR Apache-2.0 / <code>npx owlwarden turn</code></p>
</footer>
</body>
</html>
`);
}

/** Keeps generated copy on plain punctuation across metadata and page text. */
function normalizeSiteCopy(html) {
  return html
    .replaceAll("·", "/")
    .replaceAll("—", "-")
    .replaceAll("–", "-");
}

/** Renders the shared primary navigation with one page-aware current marker. */
function renderPrimaryNavigation(path, up) {
  const current = primarySection(path);
  return PRIMARY_NAV_ITEMS.map((item) => {
    const marker = item.section === current ? ' aria-current="page"' : "";
    return `    <a href="${up}${item.href}"${marker}>${esc(item.label)}</a>`;
  }).join("\n");
}

/** Maps related product pages to the section readers use to reach them. */
function primarySection(path) {
  if (path.startsWith("rules/")) return "Rules";
  if (
    path.startsWith("agent-config-security/") ||
    path.startsWith("claude-code/") ||
    path.startsWith("cursor/") ||
    path.startsWith("mcp/")
  ) return "Agent config";
  if (path.startsWith("vet/")) return "vet";
  if (path.startsWith("turn/")) return "turn";
  if (path.startsWith("offline/")) return "Offline";
  if (path.startsWith("owasp/") || path.startsWith("asi/")) return "Coverage";
  return undefined;
}

/** Renders the one product-hero interface used by every marketing page. */
function renderHero(page) {
  if (!page.hero) return `<h1>${esc(page.heading)}</h1>`;
  const actions = page.hero.actions
    .slice(0, 3)
    .map(
      (action) =>
        `<a class="button button-${esc(action.kind ?? "secondary")}" href="${esc(action.href)}">${esc(action.label)}</a>`,
    )
    .join("\n");

  return `<section class="page-hero">
  <div class="hero-copy">
    <p class="eyebrow">${esc(page.hero.kicker)}</p>
    <h1>${esc(page.heading)}</h1>
    <p class="hero-summary">${page.hero.summary}</p>
    <div class="hero-actions">${actions}</div>
  </div>
  ${page.hero.visual}
</section>`;
}

/** A fenced code block with a real language class. */
export function code(language, source) {
  return `<pre class="code"><code class="language-${esc(language)}">${esc(source)}</code></pre>`;
}

/** The severity chip used everywhere a finding is described. */
export function chip(kind, label) {
  return `<span class="chip chip-${esc(kind)}">${esc(label ?? kind)}</span>`;
}
