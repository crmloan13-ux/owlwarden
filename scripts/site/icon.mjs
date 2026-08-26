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
 * So this is drawn at 16px and scaled up, not the other way round. Four shapes,
 * maximum contrast, and the three features that make a shape read as an owl
 * rather than as a generic animal: two large adjacent eyes, ear tufts, and a
 * beak between them.
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
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="owlwarden">
  <title>owlwarden</title>
  <rect width="64" height="64" rx="14" fill="${THEME.ink}"/>

  <!-- Eye rings in the severity colour the reporter uses for "high", so the
       mark and the report share one accent. -->
  <circle cx="21" cy="33" r="13.4" fill="${THEME.high}"/>
  <circle cx="43" cy="33" r="13.4" fill="${THEME.high}"/>

  <!-- The face: one swept stroke from the left horn, down to the point between
       the eyes, and up to the right horn, closed across the brow. Curved rather
       than triangular — straight tufts read as goggles with eyebrows. -->
  <path d="M7.5 33
           C 5.6 20.5, 9.5 10.5, 16.8 6
           C 15.4 15.5, 17.2 22, 22.6 26.6
           L 32 35.4
           L 41.4 26.6
           C 46.8 22, 48.6 15.5, 47.2 6
           C 54.5 10.5, 58.4 20.5, 56.5 33
           C 53 25.6, 47.6 21.6, 41.6 21.4
           L 22.4 21.4
           C 16.4 21.6, 11 25.6, 7.5 33 Z"
        fill="${THEME.paper}"/>

  <!-- Eyes. Three rings is the most a 16-pixel render can hold, and it is what
       makes this read as an owl rather than as a face. -->
  <circle cx="21" cy="33" r="10.2" fill="${THEME.paper}"/>
  <circle cx="43" cy="33" r="10.2" fill="${THEME.paper}"/>
  <circle cx="21" cy="33" r="6.4" fill="${THEME.ink}"/>
  <circle cx="43" cy="33" r="6.4" fill="${THEME.ink}"/>
  <circle cx="22.3" cy="31.7" r="1.9" fill="${THEME.paper}"/>
  <circle cx="44.3" cy="31.7" r="1.9" fill="${THEME.paper}"/>

  <!-- The beak. It starts *above* the point where the brow meets rather than at
       it: a beak that merely touches the V leaves two hairline slivers of the
       eye ring showing through, which at 16 pixels is a smudge and at 512 is a
       mistake. Overlapping makes the face one shape. -->
  <path d="M32 27 L27.8 41.4 L32 50 L36.2 41.4 Z" fill="${THEME.paper}"/>
</svg>
`;
}
