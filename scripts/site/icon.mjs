import { THEME } from "./theme.mjs";

/**
 * The favicon, drawn for the size it is actually seen at.
 *
 * The previous one was a detailed mid-century illustration at 192×192. It is a
 * good drawing and it is unreadable in a browser tab: at 16 pixels the tufts,
 * the eye rings, and the registration marks collapse into a grey-brown smudge,
 * and the thing a tab needs to be is *identifiable at a glance among twenty
 * other tabs*.
 *
 * So this is drawn at 16px and scaled up, not the other way round. The short,
 * outward ear tufts belong to the head silhouette instead of growing into two
 * horns. The facial disc is one connected mask, while the gap between its two
 * halves forms the vertical centre without adding a nose or beak. Those
 * proportions keep it recognisable as an owl at tab size without turning it
 * into a detailed illustration.
 *
 * It is the same mark the CLI prints — `◉ᴥ◉` — drawn geometrically, and it uses
 * the palette derived from the reporter, so the tab, the page, and the terminal
 * are recognisably one object.
 *
 * SVG rather than PNG: it stays sharp on every display and it is under a
 * kilobyte. The PNG stays as the `apple-touch-icon`, where 192×192 is the size
 * it is actually rendered at and the illustration's detail earns its place.
 *
 * The palette is fixed rather than scheme-aware. A `prefers-color-scheme`
 * inversion sounds right and is a bug waiting to happen: the tile, the face,
 * and the eye interiors are three layers that have to stay in the right
 * contrast order, and inverting two of them is how an icon ends up as one white
 * mass. An ink tile with a paper face reads on a light tab strip and a dark one
 * alike, and it looks the same everywhere, which is what a mark is for.
 */
export function favicon() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="owlwarden" data-brand="owlwarden-guardian" shape-rendering="geometricPrecision">
  <title>owlwarden</title>
  <rect width="64" height="64" rx="14" fill="${THEME.ink}"/>

  <!-- Short outward tufts, a broad crown, and a tapered lower face. -->
  <g id="owl-head">
    <path d="M10 29
             C10 19.6 18.8 12.5 32 12.5
             C45.2 12.5 54 19.6 54 29
             C54 40.2 47.1 49.2 38.4 53.5
             L32 57
             L25.6 53.5
             C16.9 49.2 10 40.2 10 29Z"
          fill="${THEME.paper}"/>
    <path d="M14.8 18.5
             C14.4 15.2 13.5 12.2 12 9.5
             C16.1 11 19.3 12.9 21.5 15.2
             C18.7 15.8 16.5 16.9 14.8 18.5Z"
          fill="${THEME.paper}"/>
    <path d="M42.5 15.2
             C44.7 12.9 47.9 11 52 9.5
             C50.5 12.2 49.6 15.2 49.2 18.5
             C47.5 16.9 45.3 15.8 42.5 15.2Z"
          fill="${THEME.paper}"/>
  </g>

  <!-- One facial disc rather than two separate goggle rings. -->
  <g id="owl-face">
    <path d="M12 31
             C12 23.2 19.7 18.2 28.2 20.2
             C29.8 20.6 31 21.4 32 22.6
             C33 21.4 34.2 20.6 35.8 20.2
             C44.3 18.2 52 23.2 52 31
             C52 39.8 44.5 46.2 35.8 44.6
             C34.1 44.3 32.9 43.5 32 42.3
             C31.1 43.5 29.9 44.3 28.2 44.6
             C19.5 46.2 12 39.8 12 31Z"
          fill="${THEME.high}"/>
  </g>

  <g id="owl-eyes">
    <circle cx="22" cy="31.5" r="9.6" fill="${THEME.paper}"/>
    <circle cx="42" cy="31.5" r="9.6" fill="${THEME.paper}"/>
    <circle cx="22" cy="31.5" r="5.3" fill="${THEME.ink}"/>
    <circle cx="42" cy="31.5" r="5.3" fill="${THEME.ink}"/>
    <circle cx="23.4" cy="30" r="1.15" fill="${THEME.paper}"/>
    <circle cx="43.4" cy="30" r="1.15" fill="${THEME.paper}"/>
  </g>

</svg>
`;
}

/** The install metadata; every raster entry is generated from {@link favicon}. */
export function webManifest() {
  return `${JSON.stringify(
    {
      name: "owlwarden",
      short_name: "owlwarden",
      description: "Local security scanner for Node apps and coding-agent configuration.",
      start_url: "./",
      scope: "./",
      display: "standalone",
      background_color: THEME.paper,
      theme_color: THEME.paper,
      icons: [
        { src: "./favicon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
        { src: "./favicon.png", sizes: "192x192", type: "image/png", purpose: "any" },
        { src: "./icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
      ],
    },
    null,
    2,
  )}\n`;
}
