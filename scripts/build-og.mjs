#!/usr/bin/env node
/**
 * Writes `site/og.svg`, and rasterises it to `site/og.png` where a rasteriser
 * exists.
 *
 *   node scripts/build-og.mjs           # SVG only
 *   node scripts/build-og.mjs --raster  # ...and PNG, on macOS
 *
 * # Why the PNG is committed rather than built
 *
 * Social platforms do not render SVG in a card, so the `og:image` has to be a
 * raster. Producing one needs either a headless browser or an image library,
 * and neither belongs in the dependency tree of a security scanner that argues
 * its dependency posture is a feature.
 *
 * So the vector source is checked in next to the raster, and this script
 * rasterises it with whatever the machine already has — on macOS, Quick Look
 * plus `sips`, both of which ship with the OS. Anyone can regenerate the PNG
 * from `site/og.svg` with any tool they like; the source is the artefact that
 * matters, and it is generated from the same palette as everything else.
 *
 * The Quick Look renderer scales an SVG to fill a square, so the card is
 * rendered on a 1200×1200 canvas with the 1200×630 design centred, and the
 * middle 630 rows are cropped back out. That is the whole reason for the
 * indirection.
 */

import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { ogCard } from "./site/og-card.mjs";

const siteDir = fileURLToPath(new URL("../site/", import.meta.url));
const card = ogCard();

await writeFile(join(siteDir, "og.svg"), card);
process.stdout.write("wrote site/og.svg\n");

if (!process.argv.includes("--raster")) {
  process.stdout.write("pass --raster to also produce og.png (macOS only)\n");
  process.exit(0);
}

if (process.platform !== "darwin") {
  process.stderr.write(
    "rasterising here needs macOS (qlmanage + sips). Convert site/og.svg to a\n" +
      "1200x630 PNG with any tool and save it as site/og.png.\n",
  );
  process.exit(1);
}

const scratch = await mkdtemp(join(tmpdir(), "owlwarden-og-"));
try {
  const inner = card.replace(/^<svg[^>]*>/, "").replace(/<\/svg>\s*$/, "");
  const square =
    '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="1200" viewBox="0 0 1200 1200">' +
    '<rect width="1200" height="1200" fill="#fbfaf8"/>' +
    '<g transform="translate(0 285)">' +
    inner +
    "</g></svg>";
  const squarePath = join(scratch, "square.svg");
  await writeFile(squarePath, square);

  execFileSync("qlmanage", ["-t", "-s", "1200", "-o", scratch, squarePath], {
    stdio: "ignore",
  });
  execFileSync("sips", [
    "--cropToHeightWidth",
    "630",
    "1200",
    join(scratch, "square.svg.png"),
    "--out",
    join(scratch, "og.png"),
  ], { stdio: "ignore" });

  await copyFile(join(scratch, "og.png"), join(siteDir, "og.png"));
  process.stdout.write("wrote site/og.png (1200x630)\n");
} finally {
  await rm(scratch, { recursive: true, force: true });
}
