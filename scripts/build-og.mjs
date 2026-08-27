#!/usr/bin/env node
/**
 * Writes `site/og.svg`, rasterises it to `site/og.png`, and generates every
 * browser/install icon from the same geometric owl mark where a rasteriser
 * exists.
 *
 *   node scripts/build-og.mjs           # SVG only
 *   node scripts/build-og.mjs --raster  # ...plus card and icon PNGs, on macOS
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
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { ogCard } from "./site/og-card.mjs";
import { favicon } from "./site/icon.mjs";

const CARD_OVERSAMPLE = 2;
const ICON_OVERSAMPLE = 4;
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

  const cardRenderSize = 1200 * CARD_OVERSAMPLE;
  execFileSync("qlmanage", ["-t", "-s", String(cardRenderSize), "-o", scratch, squarePath], {
    stdio: "ignore",
  });
  const cardOversampled = join(scratch, "og-oversampled.png");
  execFileSync("sips", [
    "--cropToHeightWidth",
    String(630 * CARD_OVERSAMPLE),
    String(cardRenderSize),
    join(scratch, "square.svg.png"),
    "--out",
    cardOversampled,
  ], { stdio: "ignore" });
  execFileSync("sips", [
    "--resampleHeightWidth",
    "630",
    "1200",
    cardOversampled,
    "--out",
    join(siteDir, "og.png"),
  ], { stdio: "ignore" });
  process.stdout.write("wrote site/og.png (1200x630)\n");
  await rasterizeIcons(scratch);
} finally {
  await rm(scratch, { recursive: true, force: true });
}

/** Rasterises every browser/install size from the same geometric owl mark. */
async function rasterizeIcons(scratch) {
  const source = join(scratch, "owlwarden-icon.svg");
  await writeFile(source, favicon());
  const renderSize = 512 * ICON_OVERSAMPLE;
  execFileSync("qlmanage", ["-t", "-s", String(renderSize), "-o", scratch, source], {
    stdio: "ignore",
  });

  const rendered = `${source}.png`;
  const outputs = [
    [512, "icon-512.png"],
    [192, "favicon.png"],
    [180, "apple-touch-icon.png"],
  ];
  for (const [size, name] of outputs) {
    execFileSync("sips", [
      "--resampleHeightWidth",
      String(size),
      String(size),
      rendered,
      "--out",
      join(siteDir, name),
    ], { stdio: "ignore" });
  }
  process.stdout.write("wrote synced site icons (180, 192, 512)\n");
}
