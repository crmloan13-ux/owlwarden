import { createServer, type Server } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { reportSchema, shouldFail } from "@dointhai/owlwarden-sdk";
import { describe, expect, it } from "vitest";

import { EXIT } from "../src/exit.js";
import { run } from "../src/run.js";

/** Finding ids every framework fixture must demonstrate (matches SHARED_FIRES). */
const SHARED_FINDING_IDS = [
  "ci-unpinned-action",
  "cors-permissive",
  "hardcoded-secret",
  "insecure-cookie",
  "open-redirect",
  "security-headers-missing",
  "sensitive-data-logged",
  "sql-injection",
  "ssrf",
  "stack-trace-leak",
  "unpinned-dependency",
  // Three weak-crypto shapes: MD5-password, Math.random session, AES-ECB.
  "weak-crypto",
  "weak-crypto",
  "weak-crypto",
] as const;

/**
 * End-to-end through the real engine.
 *
 * These need `pnpm build:native` to have run — the point is to exercise the
 * path a user takes, and mocking the addon would test the mock. If the addon is
 * missing, the failure says so clearly rather than looking like a logic bug.
 */

function fixture(name: string): string {
  return fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url));
}

/** A writable that keeps what was written. */
function capture(): Writable & { text(): string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return Object.assign(stream, { text: () => chunks.join("") });
}

async function cli(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const stdout = capture();
  const stderr = capture();
  const code = await run(argv, { stdout, stderr });
  return { code, out: stdout.text(), err: stderr.text() };
}

describe("owlwarden scan", () => {
  it("finds both fixture issues and exits 1", async () => {
    const { code, out } = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--format",
      "json",
      "--quiet",
    ]);

    expect(code).toBe(EXIT.FINDINGS);
    const report = reportSchema.parse(JSON.parse(out));
    expect(report.findings.map((finding) => finding.id).sort()).toEqual([...SHARED_FINDING_IDS].sort());
  });

  it("exits 0 on the false-positive corpus", async () => {
    // If this ever goes red, the tool has started crying wolf, which is the
    // failure that gets a scanner uninstalled.
    for (const name of ["should-not-fire/next-api-clean", "should-not-fire/tempting"]) {
      const { code, out } = await cli(["scan", fixture(name), "--format", "json", "--quiet"]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings, `${name} should be silent`).toEqual([]);
      expect(code).toBe(EXIT.CLEAN);
    }
  });

  it("does not fail the run when --fail-on is above what was found", async () => {
    const { code } = await cli([
      "scan",
      fixture("vulnerable/nest-api"),
      "--fail-on",
      "high",
      "--min-confidence",
      "confirmed",
      "--format",
      "json",
      "--quiet",
    ]);
    // Nothing reaches `confirmed` without a dynamic run, so a static-only scan
    // configured this strictly must pass.
    expect(code).toBe(EXIT.CLEAN);
  });

  it("prints a code frame in pretty output", async () => {
    const { out } = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--no-color",
      "--ascii",
      "--quiet",
    ]);
    expect(out).toContain("err.stack");
    expect(out).toContain("leaks internal stack trace to the client");
    expect(out).toContain("app/api/users/route.ts");
    expect(out).not.toContain("\u001b[");
  });

  it("reports an unreadable project instead of pretending it scanned", async () => {
    const { code, err } = await cli(["scan", fixture("does-not-exist"), "--quiet"]);
    expect(code).toBe(EXIT.ERROR);
    expect(err).toMatch(/error:/);
  });

  it("writes a baseline and then hides those findings on the next scan", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-baseline-"));
    const baselinePath = join(dir, "baseline.json");
    try {
      const write = await cli([
        "scan",
        fixture("vulnerable/next-api"),
        "--format",
        "json",
        "--quiet",
        "--write-baseline",
        baselinePath,
      ]);
      expect(write.code).toBe(EXIT.FINDINGS);
      const written = JSON.parse(await readFile(baselinePath, "utf8")) as {
        entries: unknown[];
      };
      expect(written.entries.length).toBeGreaterThan(0);

      const filtered = await cli([
        "scan",
        fixture("vulnerable/next-api"),
        "--format",
        "json",
        "--quiet",
        "--baseline",
        baselinePath,
      ]);
      const report = reportSchema.parse(JSON.parse(filtered.out));
      expect(report.findings).toEqual([]);
      expect(report.baselineHiddenCount).toBeGreaterThan(0);
      expect(filtered.code).toBe(EXIT.CLEAN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("honours a next-line suppression with a reason", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-suppress-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "suppress-fixture", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak -- fixture: prove reason works",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const { code, out, err } = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--report-suppressions",
      ]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(false);
      expect(report.suppressedCount).toBeGreaterThanOrEqual(1);
      expect(err).toContain("stack-trace-leak");
      expect(err).toContain("[active]");
      // The remaining finding is typically possible-confidence headers advice —
      // that must still appear, but must not fail the gate on its own.
      expect(report.findings.some((finding) => finding.id === "security-headers-missing")).toBe(
        true,
      );
      expect(shouldFail(report, "info", "possible")).toBe(false);
      expect(code).toBe(EXIT.CLEAN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("labels a missing-reason directive without calling it active", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-suppress-bad-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "suppress-bad", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const { out, err } = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--report-suppressions",
      ]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(true);
      expect(report.suppressedCount ?? 0).toBe(0);
      expect(err).toContain("[missing-reason]");
      expect(err).not.toContain("[active]");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("write-baseline captures the post-suppression view", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-baseline-suppress-"));
    const baselinePath = join(dir, ".owlwarden-baseline.json");
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "baseline-suppress", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak -- accepted locally",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const written = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--write-baseline",
        baselinePath,
      ]);
      // Possible-only leftovers do not fail the gate; the baseline must still
      // be written from the post-suppression view.
      expect([EXIT.CLEAN, EXIT.FINDINGS]).toContain(written.code);
      const writtenReport = reportSchema.parse(JSON.parse(written.out));
      expect(writtenReport.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(
        false,
      );
      const baseline = JSON.parse(await readFile(baselinePath, "utf8")) as {
        entries: { id: string }[];
      };
      expect(baseline.entries.some((entry) => entry.id === "stack-trace-leak")).toBe(false);

      const filtered = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--baseline",
        baselinePath,
      ]);
      const report = reportSchema.parse(JSON.parse(filtered.out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(false);
      expect(report.suppressedCount).toBeGreaterThanOrEqual(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("CI security posture", () => {
  it("ignores inline suppressions under --ci unless opted in", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-ci-suppress-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "ci-suppress", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try { return NextResponse.json({ ok: true }) }",
          "  catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak -- silence the gate",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const denied = await cli(["scan", dir, "--ci", "--fail-on", "medium"]);
      expect(denied.code).toBe(EXIT.FINDINGS);
      const deniedReport = reportSchema.parse(JSON.parse(denied.out));
      expect(deniedReport.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(
        true,
      );
      expect(deniedReport.suppressedCount).toBe(0);
      expect(denied.err).toMatch(/ignores inline suppressions/);

      const allowed = await cli([
        "scan",
        dir,
        "--ci",
        "--fail-on",
        "medium",
        "--allow-suppressions",
      ]);
      const allowedReport = reportSchema.parse(JSON.parse(allowed.out));
      expect(allowedReport.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(
        false,
      );
      expect(allowedReport.suppressedCount).toBeGreaterThanOrEqual(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses --baseline under --ci without --allow-baseline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-ci-baseline-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "ci-baseline", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(join(dir, "route.ts"), "export const GET = () => null\n");
      const baselinePath = join(dir, "base.json");
      await writeFile(
        baselinePath,
        JSON.stringify({
          schemaVersion: 1,
          engineVersion: "0.0.0",
          createdAt: "1970-01-01T00:00:00Z",
          entries: [],
        }),
      );

      const { code, err } = await cli([
        "scan",
        dir,
        "--ci",
        "--baseline",
        baselinePath,
      ]);
      expect(code).toBe(EXIT.ERROR);
      expect(err).toMatch(/--allow-baseline/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("ignores hostile minConfidence in project JSON under --ci", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-ci-gate-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "ci-gate", dependencies: { next: "^14.2.0" } }),
      );
      // Confirmed is unreachable for static rules — if honoured, the scan goes green.
      await writeFile(
        join(dir, "owlwarden.config.json"),
        JSON.stringify({ minConfidence: "confirmed", failOn: "high" }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try { return NextResponse.json({ ok: true }) }",
          "  catch (err) { return NextResponse.json({ error: (err as Error).stack }) }",
          "}",
          "",
        ].join("\n"),
      );

      const silenced = await cli(["scan", dir, "--ci", "--fail-on", "medium"]);
      expect(silenced.code).toBe(EXIT.FINDINGS);
      const report = reportSchema.parse(JSON.parse(silenced.out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(true);

      // Opt-in restores project config — and the hostile knobs win.
      const trusted = await cli([
        "scan",
        dir,
        "--ci",
        "--fail-on",
        "medium",
        "--allow-project-config",
      ]);
      expect(trusted.code).toBe(EXIT.CLEAN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not execute owlwarden.config.mjs under --ci", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-ci-config-"));
    const marker = join(dir, "pwned.marker");
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "ci-config", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "owlwarden.config.mjs"),
        `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'pwned');\nexport default { failOn: 'high' };\n`,
      );
      await writeFile(join(dir, "route.ts"), "export const GET = () => null\n");

      const { code } = await cli(["scan", dir, "--ci"]);
      // Scan still runs (findings or clean); the marker must never appear.
      expect([EXIT.CLEAN, EXIT.FINDINGS]).toContain(code);
      await expect(readFile(marker, "utf8")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("redacts hardcoded-secret values from CI JSON snippets", async () => {
    const { code, out } = await cli([
      "scan",
      fixture("vulnerable/express-api"),
      "--ci",
      "--fail-on",
      "info",
    ]);
    expect(code).toBe(EXIT.FINDINGS);
    const report = reportSchema.parse(JSON.parse(out));
    const secretFinding = report.findings.find((finding) => finding.id === "hardcoded-secret");
    expect(secretFinding).toBeDefined();
    const blob = JSON.stringify(secretFinding);
    expect(blob).not.toContain("sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx");
    expect(blob).toContain("sk_l***");
    // Prefix of a long secret must not survive truncation either.
    expect(blob).not.toMatch(/sk_live_51Nx-AbCdEfGhIjKlMnOp/);
  });

  it("refuses --out under a symlinked directory", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-out-symlink-"));
    try {
      const outside = join(dir, "outside");
      await mkdir(outside);
      const link = join(dir, "out");
      await symlink(outside, link);

      const { code, err } = await cli([
        "scan",
        fixture("should-not-fire/next-api-clean"),
        "--format",
        "json",
        "--quiet",
        "--out",
        join(link, "report.json"),
      ]);
      expect(code).toBe(EXIT.ERROR);
      expect(err).toMatch(/symlinked directory/);
      expect(await readdir(outside)).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses --write-baseline under a symlinked directory", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-baseline-symlink-"));
    try {
      const outside = join(dir, "outside");
      await mkdir(outside);
      const link = join(dir, "base");
      await symlink(outside, link);

      const { code, err } = await cli([
        "scan",
        fixture("should-not-fire/next-api-clean"),
        "--format",
        "json",
        "--quiet",
        "--write-baseline",
        join(link, "baseline.json"),
      ]);
      expect(code).toBe(EXIT.ERROR);
      expect(err.length).toBeGreaterThan(0);
      expect(await readdir(outside)).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("treats a truncated report as a failing CI gate", () => {
    // Mirrors the engine: flood → truncated → exit 1 even with no retained
    // findings under a strict gate. Full flood coverage lives in the Rust
    // scheduler tests; this pins the CLI's shouldFail import.
    const truncated = reportSchema.parse({
      schemaVersion: "1.0",
      tool: { name: "owlwarden", version: "0.0.0" },
      scannedAt: "1970-01-01T00:00:00Z",
      durationMs: 0,
      target: {
        project: ".",
        scope: [],
        filesScanned: 0,
        routesProbed: 0,
        preset: "quick",
      },
      summary: { high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      suppressedCount: 0,
      suppressions: [],
      baselineHiddenCount: 0,
      truncated: true,
      errors: [],
    });
    expect(shouldFail(truncated, "high", "confirmed")).toBe(true);
  });

  it("--ci still exits 1 on findings and 0 on clean fixtures", async () => {
    const dirty = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--ci",
      "--fail-on",
      "medium",
    ]);
    expect(dirty.code).toBe(EXIT.FINDINGS);
    reportSchema.parse(JSON.parse(dirty.out));

    const clean = await cli([
      "scan",
      fixture("should-not-fire/next-api-clean"),
      "--ci",
      "--fail-on",
      "info",
    ]);
    expect(clean.code).toBe(EXIT.CLEAN);
    const report = reportSchema.parse(JSON.parse(clean.out));
    expect(report.findings).toEqual([]);
  });
});

describe.sequential("owlwarden scan --target (live correlation)", () => {
  async function withServer(
    handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void,
    run: (target: string) => Promise<void>,
  ): Promise<void> {
    const server: Server = createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("expected a TCP address");
      }
      await run(`http://127.0.0.1:${address.port}/`);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  }

  /** Node strips the body on HEAD; a Content-Length that promises bytes hangs reqwest. */
  function respond(res: import("node:http").ServerResponse, headers: Record<string, string>, body = "") {
    res.writeHead(200, headers);
    res.end(body);
  }

  it("raises security-headers-missing to confirmed when the live target agrees", async () => {
    const hits: string[] = [];
    await withServer(
      (req, res) => {
        hits.push(`${req.method} ${req.url}`);
        // Never advertise a body length on HEAD — Node omits the body and
        // reqwest would wait forever for the promised bytes.
        respond(res, { "Content-Type": "text/plain" }, req.method === "HEAD" ? "" : "ok");
      },
      async (target) => {
        const { code, out, err } = await cli([
          "scan",
          fixture("vulnerable/next-api"),
          "--target",
          target,
          "--format",
          "json",
          "--quiet",
        ]);

        expect(code).toBe(EXIT.FINDINGS);
        const report = reportSchema.parse(JSON.parse(out));
        expect(hits, `probe never reached ${target}; errors=${JSON.stringify(report.errors)} err=${err}`).not.toEqual(
          [],
        );
        expect(report.target.routesProbed).toBeGreaterThanOrEqual(1);
        const headers = report.findings.filter(
          (finding) => finding.id === "security-headers-missing",
        );
        expect(headers).toHaveLength(1);
        const [finding] = headers;
        if (finding === undefined) {
          throw new Error("expected a security-headers-missing finding");
        }
        expect(finding.confidence).toBe("confirmed");
        expect(finding.context?.evidence ?? "").toMatch(/confirmed at runtime/);
        expect(finding.location).toHaveProperty("path");
      },
    );
  }, 30_000);

  it("clears the static headers gap when the live target already sets them", async () => {
    const present = {
      "Strict-Transport-Security": "max-age=63072000",
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    };
    await withServer(
      (_req, res) => {
        respond(res, present);
      },
      async (target) => {
        const { out } = await cli([
          "scan",
          fixture("vulnerable/express-api"),
          "--target",
          target,
          "--format",
          "json",
          "--quiet",
        ]);

        const report = reportSchema.parse(JSON.parse(out));
        expect(report.target.routesProbed).toBeGreaterThanOrEqual(1);
        expect(report.findings.some((finding) => finding.id === "security-headers-missing")).toBe(
          false,
        );
      },
    );
  }, 30_000);

  it("keeps the clean corpus silent when the live target also has headers", async () => {
    const present = {
      "Strict-Transport-Security": "max-age=63072000",
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    };
    await withServer(
      (_req, res) => {
        respond(res, present);
      },
      async (target) => {
        for (const name of [
          "should-not-fire/next-api-clean",
          "should-not-fire/nuxt-api-clean",
          "should-not-fire/nest-api-clean",
          "should-not-fire/express-api-clean",
          "should-not-fire/fastify-api-clean",
        ]) {
          const { code, out } = await cli([
            "scan",
            fixture(name),
            "--target",
            target,
            "--format",
            "json",
            "--quiet",
          ]);
          const report = reportSchema.parse(JSON.parse(out));
          expect(
            report.findings.filter((finding) => finding.id === "security-headers-missing"),
            `${name} must stay silent on headers with agreeing runtime`,
          ).toEqual([]);
          expect(code).toBe(EXIT.CLEAN);
        }
      },
    );
  }, 60_000);

  it("covers every framework fixture with confirmed correlation", async () => {
    await withServer(
      (_req, res) => {
        respond(res, { "Content-Type": "text/plain" });
      },
      async (target) => {
        for (const name of [
          "vulnerable/next-api",
          "vulnerable/nuxt-api",
          "vulnerable/nest-api",
          "vulnerable/express-api",
          "vulnerable/fastify-api",
        ]) {
          const { out } = await cli([
            "scan",
            fixture(name),
            "--target",
            target,
            "--format",
            "json",
            "--quiet",
          ]);
          const report = reportSchema.parse(JSON.parse(out));
          expect(report.target.routesProbed, `${name} probed`).toBeGreaterThanOrEqual(1);
          const headers = report.findings.filter(
            (finding) => finding.id === "security-headers-missing",
          );
          expect(headers, `${name} should confirm headers`).toHaveLength(1);
          expect(headers[0]?.confidence).toBe("confirmed");
        }
      },
    );
  }, 60_000);
});

describe("owlwarden rules / explain", () => {
  it("lists rules as JSON", async () => {
    const { code, out } = await cli(["rules", "--json"]);
    expect(code).toBe(EXIT.CLEAN);
    expect((JSON.parse(out) as unknown[]).length).toBeGreaterThan(0);
  });

  it("explains a rule completely offline", async () => {
    const { code, out } = await cli(["explain", "stack-trace-leak"]);
    expect(code).toBe(EXIT.CLEAN);
    expect(out).toContain("CWE-209");
    // An agent reading this has no browser: the fix has to be in the output.
    expect(out).toContain("FIXES");
    expect(out).toContain("NextResponse.json");
  });

  it("does not invent an answer for an unknown rule", async () => {
    const { code, err } = await cli(["explain", "no-such-rule"]);
    expect(code).toBe(EXIT.ERROR);
    expect(err).toContain("owlwarden rules");
  });
});
