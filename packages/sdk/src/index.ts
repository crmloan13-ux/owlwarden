/**
 * `@dointhai/owlwarden-sdk` — the report format, as TypeScript types and zod schemas.
 *
 * Anything that reads owlwarden output should depend on this rather than on
 * hand-written interfaces: these schemas are checked against the Rust engine on
 * every CI run, hand-written ones are checked by nobody.
 *
 * Plugin-authoring types are not here yet. They land with the plugin host in
 * v0.2 (`ROADMAP.md`), and publishing an interface that nothing loads would be
 * a promise we have not kept.
 */
export * from "./report.js";
