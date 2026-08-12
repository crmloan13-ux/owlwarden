import { describe, expect, it } from "vitest";

import { ArgError, parse } from "../src/args.js";

describe("parse", () => {
  it("shows help rather than scanning when given nothing", () => {
    // A scanner that starts work you did not ask for is a scanner you stop
    // trusting with a path argument.
    expect(parse([])).toEqual({ command: "help" });
  });

  it("leaves unset options absent so config can supply them", () => {
    const cli = parse(["scan"]);
    expect(cli.command).toBe("scan");
    if (cli.command !== "scan") return;
    expect(cli.options.path).toBe(".");
    expect("preset" in cli.options).toBe(false);
    expect("failOn" in cli.options).toBe(false);
  });

  it("treats --ci as a shorthand, not a mode", () => {
    const cli = parse(["scan", "--ci"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.format).toBe("json");
    expect(cli.options.formats).toEqual(["json"]);
    expect(cli.options.quiet).toBe(true);
    expect(cli.options.color).toBe(false);
  });

  it("lets --format override the one --ci implies", () => {
    const cli = parse(["scan", "--ci", "--format", "pretty"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.format).toBe("pretty");
    expect(cli.options.formats).toEqual(["pretty"]);
  });

  it("stacks repeated --format, ignores duplicates, preserves order", () => {
    const cli = parse([
      "scan",
      "--format",
      "sarif",
      "--format",
      "pretty",
      "--format",
      "sarif",
      "--format",
      "json",
    ]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.formats).toEqual(["sarif", "pretty", "json"]);
    expect(cli.options.format).toBe("sarif");
  });

  it("rejects an unknown format value", () => {
    expect(() => parse(["scan", "--format", "yaml"])).toThrow(
      /pretty, json, sarif, junit, md/,
    );
  });

  it("accepts a path alongside flags", () => {
    const cli = parse(["scan", "./apps/api", "--preset", "deep", "--fail-on", "high"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.path).toBe("./apps/api");
    expect(cli.options.preset).toBe("deep");
    expect(cli.options.failOn).toBe("high");
  });

  it("rejects a mistyped flag instead of falling back to the default", () => {
    expect(() => parse(["scan", "--presset", "deep"])).toThrow(ArgError);
  });

  it("rejects an unknown command", () => {
    expect(() => parse(["scna"])).toThrow(/unknown command/);
  });

  it("lists the accepted values for a bad level", () => {
    expect(() => parse(["scan", "--fail-on", "critical"])).toThrow(
      /high, medium, low, info/,
    );
  });

  it("refuses a second path rather than guessing which one is meant", () => {
    expect(() => parse(["scan", "a", "b"])).toThrow(/at most one path/);
  });

  it("requires a rule id for explain", () => {
    expect(() => parse(["explain"])).toThrow(/requires a rule id/);
    expect(parse(["explain", "stack-trace-leak"])).toEqual({
      command: "explain",
      rule: "stack-trace-leak",
      json: false,
    });
  });

  it("parses watch with the same options as scan", () => {
    const cli = parse(["watch", "./app", "--baseline", ".owlwarden-baseline.json"]);
    expect(cli.command).toBe("watch");
    if (cli.command !== "watch") return;
    expect(cli.options.path).toBe("./app");
    expect(cli.options.baseline).toBe(".owlwarden-baseline.json");
  });

  it("parses baseline and suppression flags", () => {
    const cli = parse([
      "scan",
      "--write-baseline",
      "base.json",
      "--report-suppressions",
    ]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.writeBaseline).toBe("base.json");
    expect(cli.options.reportSuppressions).toBe(true);
  });

  it("parses --target and repeated --scope", () => {
    const cli = parse([
      "scan",
      "--target",
      "http://127.0.0.1:3000/",
      "--scope",
      "http://127.0.0.1:3000/",
      "--scope",
      "http://127.0.0.1:3000/api",
    ]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.target).toBe("http://127.0.0.1:3000/");
    expect(cli.options.scope).toEqual([
      "http://127.0.0.1:3000/",
      "http://127.0.0.1:3000/api",
    ]);
  });

  it("refuses --scope without --target", () => {
    expect(() => parse(["scan", "--scope", "http://127.0.0.1:3000/"])).toThrow(
      /--scope requires --target/,
    );
  });

  it("defaults scope to an empty list when omitted", () => {
    const cli = parse(["scan", "--target", "http://127.0.0.1:3000/"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.scope).toEqual([]);
  });

  it("defaults allowConfigJs to false and accepts the opt-in flag", () => {
    const denied = parse(["scan", "--ci"]);
    if (denied.command !== "scan") throw new Error("expected scan");
    expect(denied.options.allowConfigJs).toBe(false);
    expect(denied.options.ci).toBe(true);
    expect(denied.options.allowProjectConfig).toBe(false);
    expect(denied.options.allowSuppressions).toBe(false);
    expect(denied.options.allowBaseline).toBe(false);

    const allowed = parse([
      "scan",
      "--ci",
      "--allow-config-js",
      "--allow-project-config",
      "--allow-suppressions",
      "--allow-baseline",
    ]);
    if (allowed.command !== "scan") throw new Error("expected scan");
    expect(allowed.options.allowConfigJs).toBe(true);
    expect(allowed.options.allowProjectConfig).toBe(true);
    expect(allowed.options.allowSuppressions).toBe(true);
    expect(allowed.options.allowBaseline).toBe(true);
  });

  it("parses plugin inspect", () => {
    expect(parse(["plugin", "inspect", "./acme"])).toEqual({
      command: "plugin-inspect",
      path: "./acme",
    });
    expect(() => parse(["plugin", "inspect"])).toThrow(/requires a path/);
  });

  it("parses mcp, init, and plugin scaffold", () => {
    expect(parse(["mcp", "./apps/api"])).toEqual({
      command: "mcp",
      path: "./apps/api",
    });
    expect(parse(["init"])).toEqual({
      command: "init",
      agentRules: true,
      workflow: true,
      mcp: true,
      force: false,
    });
    expect(parse(["init", "--agent-rules"])).toEqual({
      command: "init",
      agentRules: true,
      workflow: false,
      mcp: false,
      force: false,
    });
    expect(parse(["init", "--agent-rules", "--out", "rules.md"])).toEqual({
      command: "init",
      agentRules: true,
      workflow: false,
      mcp: false,
      force: false,
      out: "rules.md",
    });
    expect(parse(["init", "--workflow", "--mcp", "--force"])).toEqual({
      command: "init",
      agentRules: false,
      workflow: true,
      mcp: true,
      force: true,
    });
    expect(parse(["plugin", "scaffold", "acme-rules"])).toEqual({
      command: "plugin-scaffold",
      name: "acme-rules",
    });
  });

  it("parses --plugin and --allow-plugins", () => {
    const cli = parse([
      "scan",
      "--plugin",
      "./my-plugin",
      "--plugin",
      "./other",
      "--allow-plugins",
    ]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.plugins).toEqual(["./my-plugin", "./other"]);
    expect(cli.options.allowPlugins).toBe(true);
  });

  it("parses --require-signed-plugins", () => {
    const cli = parse(["scan", "--require-signed-plugins"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.requireSignedPlugins).toBe(true);
  });

  it("requires a name for plugin scaffold", () => {
    expect(() => parse(["plugin", "scaffold"])).toThrow(/requires a name/);
    expect(() => parse(["plugin", "build"])).toThrow(/usage:/);
  });

  it("parses --fix flags and rejects invalid combinations", () => {
    const cli = parse(["scan", "--fix", "--dry-run", "--allow-dirty"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.fix).toBe(true);
    expect(cli.options.dryRun).toBe(true);
    expect(cli.options.allowDirty).toBe(true);
    expect(() => parse(["scan", "--fix-unsafe"])).toThrow(/requires --fix/);
    expect(() => parse(["scan", "--fix", "--ci"])).toThrow(/cannot be combined with --ci/);
    expect(() => parse(["scan", "--allow-active"])).toThrow(/requires --target/);
    const osv = parse(["scan", "--osv"]);
    if (osv.command !== "scan") throw new Error("expected scan");
    expect(osv.options.osv).toBe(true);
    const offline = parse(["scan", "--osv", "--offline", "--osv-db", ".owlwarden/osv-index.json"]);
    if (offline.command !== "scan") throw new Error("expected scan");
    expect(offline.options.offline).toBe(true);
    expect(offline.options.osvDb).toBe(".owlwarden/osv-index.json");
    expect(() => parse(["scan", "--osv", "--offline"])).toThrow(/requires --osv-db/);
    const update = parse(["osv", "update", "./app", "--out", "idx.json"]);
    if (update.command !== "osv-update") throw new Error("expected osv-update");
    expect(update.path).toBe("./app");
    expect(update.out).toBe("idx.json");
  });
});
