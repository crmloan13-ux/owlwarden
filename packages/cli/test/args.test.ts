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
    expect(cli.options.quiet).toBe(true);
    expect(cli.options.color).toBe(false);
  });

  it("lets --format override the one --ci implies", () => {
    const cli = parse(["scan", "--ci", "--format", "pretty"]);
    if (cli.command !== "scan") throw new Error("expected scan");
    expect(cli.options.format).toBe("pretty");
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
});
