import { chip, code, esc } from "./layout.mjs";
import { productVisual } from "./marketing.mjs";
import { renderFrame } from "./samples.mjs";

/**
 * The rule pages: 25 of them, plus one per (rule, profile) cell that has a
 * verified example.
 *
 * This is the part of the site that is generated from the same source that
 * generates `RULES.md`, and it is the reason the site can have a few hundred
 * pages without any of them being filler. Each cell carries something no other
 * page has: the vulnerable code *for that framework or host*, taken from a
 * fixture the test suite asserts on, and the fix written for it.
 *
 * Cross-linked along both axes, which is most of what makes a set of generated
 * pages legible rather than a farm: a rule page links to its profile variants,
 * and a profile variant links to the other rules for the same profile.
 */

/** Display names, matching `Framework::label` and `AgentHost::label` in Rust. */
/**
 * Short labels for `<title>`, where 60 characters is the whole budget.
 *
 * Only the profiles whose display name is long enough to overflow. The `<h1>`
 * and the body always use the full name — a title is a slot, not a rename.
 */
const SHORT_LABELS = {
  "tanstack-start": "TanStack",
  copilot: "Copilot",
  "gemini-cli": "Gemini",
  vscode: "VS Code",
  "claude-code": "Claude Code",
};

const PROFILE_LABELS = {
  next: "Next.js",
  nuxt: "Nuxt",
  nest: "NestJS",
  express: "Express",
  fastify: "Fastify",
  hono: "Hono",
  koa: "Koa",
  hapi: "Hapi",
  sails: "Sails.js",
  astro: "Astro",
  remix: "Remix",
  gatsby: "Gatsby",
  sveltekit: "SvelteKit",
  "tanstack-start": "TanStack Start",
  solidstart: "SolidStart",
  elysia: "Elysia",
  "claude-code": "Claude Code",
  cursor: "Cursor",
  vscode: "VS Code",
  copilot: "GitHub Copilot",
  codex: "Codex CLI",
  "gemini-cli": "Gemini CLI",
  generic: "any host",
};

export function profileLabel(id) {
  return PROFILE_LABELS[id] ?? id;
}

/** What a runtime is called on a page, as opposed to on the wire. */
const RUNTIME_LABELS = {
  node: "Node.js",
  bun: "Bun",
  deno: "Deno",
  webWorker: "Workers and other fetch-API runtimes",
};

/** The profile key on a fix object, whichever surface it came from. */
function fixProfile(fix) {
  return fix.host ?? fix.framework ?? null;
}

/**
 * Builds every rule page and every profile variant.
 *
 * @returns {Array<{path: string, page: object}>}
 */
export function rulePages({ rules, explain, samples, coverage }) {
  const pages = [];
  const bySurface = { webApp: [], agentWorkspace: [] };
  for (const rule of rules) bySurface[rule.surface ?? "webApp"].push(rule);

  // Which profiles each rule has a real example for. Computed once, because
  // both the rule page and the index need it and recomputing invites drift.
  const covered = new Map();
  for (const rule of rules) {
    const perProfile = samples.get(rule.id) ?? new Map();
    const fixes = explain.get(rule.id)?.fixes ?? [];
    covered.set(
      rule.id,
      // Deduplicated, because a runtime delta is a *second* fix carrying the
      // same framework. It belongs on that framework's page as an extra
      // section, not as a second page claiming the same URL.
      [
        ...new Set(
          fixes
            .filter((fix) => fix.runtime === undefined)
            .map(fixProfile)
            .filter((profile) => profile !== null && perProfile.has(profile)),
        ),
      ],
    );
  }

  pages.push({ path: "rules/", page: rulesIndex({ rules, bySurface, covered, coverage }) });

  for (const rule of rules) {
    const fixes = explain.get(rule.id)?.fixes ?? [];
    const perProfile = samples.get(rule.id) ?? new Map();
    const profiles = covered.get(rule.id) ?? [];

    pages.push({
      path: `rules/${rule.id}/`,
      page: rulePage({ rule, fixes, perProfile, profiles, rules }),
    });

    for (const profile of profiles) {
      pages.push({
        path: `rules/${rule.id}/${profile}/`,
        page: profilePage({
          rule,
          profile,
          fix: fixes.find(
            (entry) => fixProfile(entry) === profile && entry.runtime === undefined,
          ),
          // Every runtime this rule patches for this framework, so the page can
          // say what changes where — which is the whole point of the overlay.
          deltas: fixes.filter(
            (entry) => fixProfile(entry) === profile && entry.runtime !== undefined,
          ),
          generic: fixes.find((entry) => fixProfile(entry) === null),
          finding: perProfile.get(profile),
          siblings: rules.filter(
            (other) =>
              other.id !== rule.id && (covered.get(other.id) ?? []).includes(profile),
          ),
        }),
      });
    }
  }

  return pages;
}

// ---------------------------------------------------------------------------

function rulesIndex({ rules, bySurface, covered, coverage }) {
  const cells = rules.reduce((total, rule) => total + (covered.get(rule.id)?.length ?? 0), 0);

  const section = (title, list, blurb) => `
<h2>${esc(title)}</h2>
<p>${blurb}</p>
<ul class="cards">
${list
  .map(
    (rule) => `  <li><a href="../rules/${esc(rule.id)}/">
    <span class="name">${esc(rule.id)}</span>
    <span class="blurb">${chip(rule.severity)} ${esc(rule.title)}</span>
  </a></li>`,
  )
  .join("\n")}
</ul>`;

  return {
    title: `All ${rules.length} rules`,
    heading: `${rules.length} security rules for Node apps and agent config`,
    description:
      `All ${rules.length} owlwarden rules with the vulnerable pattern, the corrected code for ` +
      `each of ${cells} framework and agent-host combinations, and a command to check your own repo.`,
    ogType: "website",
    hero: {
      kicker: "Rule reference",
      summary: `<strong>Each page shows the trigger, confidence, and fix.</strong> Examples come from tested fixtures, and framework variants use the APIs the scanner detected.`,
      actions: [
        { label: "Install from npm", href: "https://www.npmjs.com/package/owlwarden", kind: "primary" },
        { label: "Review OWASP coverage", href: "../owasp/", kind: "secondary" },
      ],
      visual: productVisual({
        label: "compiled-in catalogue",
        title: `${rules.length} rules, ${cells} framework and host fixes`,
        items: [
          { tag: String(bySurface.webApp.length).padStart(2, "0"), title: "Application rules", detail: "Framework-aware checks for Node source." },
          { tag: String(bySurface.agentWorkspace.length).padStart(2, "0"), title: "Agent rules", detail: "Hooks, MCP, instructions, and editor config." },
          { tag: String(cells), title: "Verified variants", detail: "Each example comes from a fixture the tests assert on." },
        ],
        footer: "Generated from compiled rule metadata and tested fixtures",
      }),
    },
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Rules", href: "rules/" },
    ],
    schema: [
      {
        "@type": "CollectionPage",
        name: `owlwarden rules`,
        description: `${rules.length} security rules for Node web applications and AI coding agents.`,
      },
    ],
    body: `
${code("bash", "npx owlwarden scan          # your app\nnpx owlwarden vet .         # your agent's config")}

${section(
  "Application source",
  bySurface.webApp,
  `${bySurface.webApp.length} rules that read the code in your repository. ` +
    `<a href="../owasp/">${coverage.categoriesCovered} of 10 OWASP Top 10 (2021) categories</a> ` +
    `have at least one rule, and the ones that do not are listed too.`,
)}

${section(
  "Agent and editor configuration",
  bySurface.agentWorkspace,
  `${bySurface.agentWorkspace.length} rules that read the files your agent loads out of the working ` +
    `tree. See ` +
    `<a href="../agent-config-security/">what that surface is</a> and ` +
    `<a href="../asi/">the ASI ${esc(coverage.asiEdition)} coverage</a>.`,
)}

<h2>What a rule page tells you</h2>
<p>
  The trigger, impact, example, fix for the selected framework, taxonomy
  mapping, and commands to reproduce the check locally.
</p>
`,
  };
}

// ---------------------------------------------------------------------------

function rulePage({ rule, fixes, perProfile, profiles, rules }) {
  const generic = fixes.find((fix) => fixProfile(fix) === null);
  const example = profiles.map((profile) => perProfile.get(profile)).find(Boolean);
  const surface = rule.surface ?? "webApp";
  const related = rules
    .filter((other) => other.id !== rule.id && other.category === rule.category)
    .slice(0, 4);

  const taxonomy = [
    rule.owasp ? `<a href="../../owasp/">OWASP ${esc(rule.owasp)}</a>` : null,
    rule.asi ? `<a href="../../asi/">ASI ${esc(rule.asi)}</a>` : null,
    rule.cwe
      ? `<a href="https://cwe.mitre.org/data/definitions/${rule.cwe}.html" rel="noopener">CWE-${rule.cwe}</a>`
      : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return {
    // The id, not the sentence. It is short enough to survive truncation, and
    // it is what someone types when they have already seen the finding — which
    // is the traffic this page is for.
    title: `${rule.id} — owlwarden rule`,
    heading: rule.title,
    description: truncate(rule.description, 160),
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Rules", href: "rules/" },
      { label: rule.id, href: `rules/${rule.id}/` },
    ],
    schema: [
      {
        "@type": "TechArticle",
        "@id": `#rule`,
        headline: rule.title,
        description: rule.description,
        proficiencyLevel: "Beginner",
        about: [
          rule.cwe
            ? {
                "@type": "Thing",
                name: `CWE-${rule.cwe}`,
                url: `https://cwe.mitre.org/data/definitions/${rule.cwe}.html`,
              }
            : null,
          rule.owasp
            ? { "@type": "Thing", name: `OWASP ${rule.owasp}`, url: "https://owasp.org/Top10/" }
            : null,
          rule.asi ? { "@type": "Thing", name: `ASI ${rule.asi}`, url: "https://genai.owasp.org/" } : null,
        ].filter(Boolean),
      },
    ],
    body: `
<p class="lede">${esc(rule.description)}</p>

<p>
  ${chip(rule.severity)} ${chip(rule.maxConfidence)}
  <span class="chip chip-scope">${esc(surface === "webApp" ? "application source" : "agent workspace")}</span>
  ${taxonomy}
</p>

${
  example
    ? `<h2>What it looks like</h2>
${renderFrame(example, esc)}
<p>
  From <code>${esc(example.location.path ?? "")}</code> in the fixture suite.
  The fixture test asserts this finding.
</p>`
    : ""
}

<h2>How to fix it</h2>
<p>${esc(generic?.summary ?? "")}</p>
${generic?.patch ? code("ts", generic.patch) : ""}

${
  profiles.length > 0
    ? `<h2>The fix for your ${surface === "webApp" ? "framework" : "agent host"}</h2>
<p>
  ${surface === "webApp" ? "Choose the API used by your project" : "Choose the configuration format used by your host"}.
</p>
<ul class="pill-row">
${profiles
  .map(
    (profile) =>
      `  <li><a href="./${esc(profile)}/">${esc(profileLabel(profile))}</a></li>`,
  )
  .join("\n")}
</ul>`
    : ""
}

<h2>Check your own repository</h2>
${code("bash", `npx owlwarden scan --preset deep\nnpx owlwarden explain ${rule.id}`)}
<p>
  <code>explain</code> prints the rule and fixes in the terminal. It does not
  use the network.
</p>

${
  related.length > 0
    ? `<h2>Related rules</h2>
<ul class="cards">
${related
  .map(
    (other) => `  <li><a href="../${esc(other.id)}/">
    <span class="name">${esc(other.id)}</span>
    <span class="blurb">${chip(other.severity)} ${esc(other.title)}</span>
  </a></li>`,
  )
  .join("\n")}
</ul>`
    : ""
}

<p><a href="../">All ${esc(String(rules.length))} rules</a> · <a href="../../">owlwarden</a></p>
`,
  };
}

// ---------------------------------------------------------------------------

function profilePage({ rule, profile, fix, deltas = [], generic, finding, siblings }) {
  const label = profileLabel(profile);
  const surface = rule.surface ?? "webApp";
  const noun = surface === "webApp" ? "framework" : "agent host";

  // The `<h1>` is the query someone types, in natural language. The `<title>`
  // is the same query with the rule id in it, because that is what someone who
  // has *already seen the finding* searches — and it is short enough that a
  // result never truncates it mid-word.
  const heading = `Fix ${lowerFirst(rule.title)} in ${label}`;
  const description = writtenDescription(rule, label);

  return {
    title: `Fix ${rule.id} in ${SHORT_LABELS[profile] ?? label}`,
    heading,
    description,
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Rules", href: "rules/" },
      { label: rule.id, href: `rules/${rule.id}/` },
      { label, href: `rules/${rule.id}/${profile}/` },
    ],
    schema: [
      {
        "@type": "TechArticle",
        headline: heading,
        description: rule.description,
        proficiencyLevel: "Beginner",
        dependencies: label,
        isPartOf: { "@type": "TechArticle", "@id": `${"../".repeat(0)}#rule` },
        about: [
          rule.cwe
            ? {
                "@type": "Thing",
                name: `CWE-${rule.cwe}`,
                url: `https://cwe.mitre.org/data/definitions/${rule.cwe}.html`,
              }
            : null,
        ].filter(Boolean),
      },
      {
        "@type": "HowTo",
        name: heading,
        totalTime: "PT2M",
        step: [
          { "@type": "HowToStep", name: "Find it", text: `Run npx owlwarden scan in your ${label} project.` },
          { "@type": "HowToStep", name: "Fix it", text: fix?.summary ?? generic?.summary ?? "" },
          {
            "@type": "HowToStep",
            name: "Confirm it",
            text: `Run npx owlwarden scan again; the ${rule.id} finding is gone.`,
          },
        ],
      },
    ],
    body: `
<p class="lede">${esc(rule.description)}</p>

<p>
  ${chip(rule.severity)} ${chip(rule.maxConfidence)}
  <span class="chip chip-scope">${esc(label)}</span>
  ${rule.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${rule.cwe}.html" rel="noopener">CWE-${rule.cwe}</a>` : ""}
  ${rule.owasp ? ` · <a href="../../../owasp/">OWASP ${esc(rule.owasp)}</a>` : ""}
  ${rule.asi ? ` · <a href="../../../asi/">ASI ${esc(rule.asi)}</a>` : ""}
</p>

<h2>The vulnerable pattern in ${esc(label)}</h2>
${renderFrame(finding, esc)}
<p>
  This finding comes from the ${esc(label)} fixture in the owlwarden test
  suite${finding?.context?.route ? `, in <code>${esc([finding.context.method, finding.context.route].filter(Boolean).join(" "))}</code>` : ""}.
  ${esc(finding?.why ?? "")}
</p>

<h2>The corrected ${esc(surface === "webApp" ? "handler" : "configuration")}</h2>
<p>${esc(fix?.summary ?? generic?.summary ?? "")}</p>
${fix?.patch ? code(surface === "webApp" ? "ts" : "json", fix.patch) : ""}

${
  deltas.length > 0
    ? `<h2>On a different runtime</h2>
<p>
  The fix above is written for the runtime ${esc(label)} usually runs on. These
  are the runtimes where it would not run at all — an import that does not
  exist, or an API the host does not have — and what to write instead.
</p>
${deltas
  .map(
    (delta) => `<h3>${esc(RUNTIME_LABELS[delta.runtime] ?? delta.runtime)}</h3>
<p>${esc(delta.summary)}</p>
${delta.patch ? code("ts", delta.patch) : ""}`,
  )
  .join("\n")}`
    : ""
}

${
  generic && generic.summary !== fix?.summary
    ? `<h3>If you are not using ${esc(label)}</h3>
<p>${esc(generic.summary)}</p>`
    : ""
}

<h2>Check your own repository</h2>
${code("bash", `npx owlwarden scan\nnpx owlwarden explain ${rule.id}`)}
<p>
  Runs on your machine. <a href="../../../offline/">No account, no
  telemetry, no network unless you ask</a>. In CI, <a href="../../../ci/">SARIF
  uploads to code scanning</a> and the exit code is the gate.
</p>

${
  siblings.length > 0
    ? `<h2>Other ${esc(label)} checks</h2>
<p>
  Rules with a tested ${esc(label)} example.
</p>
<ul class="cards">
${siblings
  .map(
    (other) => `  <li><a href="../../${esc(other.id)}/${esc(profile)}/">
    <span class="name">${esc(other.id)}</span>
    <span class="blurb">${chip(other.severity)} ${esc(other.title)}</span>
  </a></li>`,
  )
  .join("\n")}
</ul>`
    : ""
}

<p>
  <a href="../">${esc(rule.id)} for every ${esc(noun)}</a> ·
  <a href="../../">All rules</a> ·
  <a href="../../../">owlwarden</a>
</p>
`,
  };
}

// ---------------------------------------------------------------------------

function lowerFirst(text) {
  return text.charAt(0).toLowerCase() + text.slice(1);
}

/**
 * A description written for the variant, not a truncated rule blurb.
 *
 * The end of a description is where the reason to click lives, and cutting a
 * sentence in half loses exactly that. So this is built from the rule's *title*
 * — which is one line by construction — and a promise that shrinks rather than
 * a lead that gets chopped.
 */
function writtenDescription(rule, label) {
  const lead = `${rule.title} in ${label}.`;
  const tails = [
    " The vulnerable pattern, the corrected code, the CWE mapping, and one command to check your own repository.",
    " The vulnerable pattern, the corrected code, and one command to check your own repository.",
    " The vulnerable pattern, the corrected code, and how to check your own repository.",
    " The vulnerable pattern, the fix, and how to check your own repo.",
  ];
  for (const tail of tails) {
    const candidate = lead + tail;
    if (candidate.length <= 164) return candidate;
  }
  // Every tail overflows, which means the title alone is nearly the budget.
  // Trim the title rather than the promise: the promise is the reason to click.
  return `${truncate(lead, 164 - tails[3].length)}${tails[3]}`;
}

function truncate(text, max) {
  const flat = text.replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  const cut = flat.slice(0, max - 1);
  return `${cut.slice(0, cut.lastIndexOf(" "))}…`;
}
