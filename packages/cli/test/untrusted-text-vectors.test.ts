import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { sanitizeAgentJson, sanitizeAgentText } from "../src/mcp/agent-safety.js";

/**
 * The shared sanitiser contract, MCP side.
 *
 * The sibling of `crates/core/tests/untrusted_text_vectors.rs`, reading the same
 * file. The two implementations exist separately on purpose — one runs inside
 * the engine, this one assembles MCP payloads and never crosses the napi
 * boundary — and the cost of that split is that they can drift without anything
 * failing. They already had: this side stripped the Unicode Tags block and the
 * Rust side did not, so a filename carrying an invisible sentence was cleaned on
 * the MCP path and passed through on the `--format agent` one.
 *
 * The fixture is now the only place the list lives.
 */

interface Case {
  name: string;
  why: string;
  input: string;
  mustNotContain: string[];
}

const cases: Case[] = await readFile(
  new URL("../../../fixtures/untrusted-text-vectors.json", import.meta.url),
  "utf8",
).then((raw) => (JSON.parse(raw) as { cases: Case[] }).cases);

it("the fixture has not quietly shrunk", () => {
  // A case is removed only when the attack it describes becomes impossible,
  // which is rare. Losing one to a bad merge should be loud.
  expect(cases.length).toBeGreaterThanOrEqual(12);
});

describe("sanitizeAgentText removes everything the vectors name", () => {
  it.each(cases.map((one) => [one.name, one] as const))("%s", (_name, one) => {
    const rendered = sanitizeAgentText(one.input);
    for (const forbidden of one.mustNotContain) {
      // Newlines are structural in MCP payloads, which are JSON rather than
      // line records, so this side keeps them. The Rust side escapes them
      // because its formats *are* line records. That difference is real and
      // deliberate, unlike the ones this file exists to catch.
      if (forbidden === "\n") continue;
      expect(
        rendered.includes(forbidden),
        `${one.name}: ${JSON.stringify(forbidden)} survived\n  why it matters: ${one.why}`,
      ).toBe(false);
    }
  });
});

describe("the vectors are hostile enough to be worth running", () => {
  it.each(cases.map((one) => [one.name, one] as const))("%s actually contains it", (_n, one) => {
    for (const forbidden of one.mustNotContain) {
      expect(
        one.input.includes(forbidden),
        `${one.name}: the input does not contain it, so the case proves nothing`,
      ).toBe(true);
    }
  });
});

describe("the sanitiser is stable under repetition and nesting", () => {
  it.each(cases.map((one) => [one.name, one] as const))("%s is idempotent", (_n, one) => {
    const once = sanitizeAgentText(one.input);
    expect(sanitizeAgentText(once)).toBe(once);
  });

  it("reaches every string in a nested payload, at any depth", () => {
    const hostile = cases[0]?.input ?? "";
    const forbidden = cases[0]?.mustNotContain[0] ?? "";
    expect(forbidden).not.toBe("");

    const payload = {
      findings: [{ location: { path: hostile }, notes: [hostile, { deeper: hostile }] }],
      count: 1,
      clean: null,
    };
    expect(JSON.stringify(sanitizeAgentJson(payload)).includes(forbidden)).toBe(false);
  });

  it("keeps the shape while changing the strings", () => {
    const sanitised = sanitizeAgentJson({ a: [1, true, null, "x"], b: { c: "y" } });
    expect(sanitised).toEqual({ a: [1, true, null, "x"], b: { c: "y" } });
  });
});

describe("a replacement that equals what it replaces is not a replacement", () => {
  // The bug this file found on its first run. `[INST]` was matched by a regex
  // and rewritten to the label `"[INST]"` — the marker spelled exactly as it
  // arrived. The substitution ran on every payload and changed nothing, and it
  // read as correct in review because that marker is already bracketed.
  it.each([
    "<|im_start|>",
    "<|im_end|>",
    "<<SYS>>",
    "<</SYS>>",
    "[INST]",
    "[/INST]",
    "<|system|>",
    "<|assistant|>",
    "<|user|>",
    "<tool_call>",
    "</tool_call>",
    "<function_call>",
    "</function_call>",
  ])("%s does not survive its own neutralisation", (marker) => {
    expect(sanitizeAgentText(marker).includes(marker)).toBe(false);
  });
});

describe("visible text is left alone", () => {
  it.each([
    "src/app/api/users/route.ts",
    'createHash("md5") is broken for anything protecting a secret',
    "ตัวอย่างภาษาไทย",
    "café — naïve — 日本語",
    "a <b> tag and a [bracket] that are not markers",
  ])("%s", (text) => {
    expect(sanitizeAgentText(text)).toBe(text);
  });
});
