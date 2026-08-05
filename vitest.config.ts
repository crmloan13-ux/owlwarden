import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    // The TS packages are small and mostly I/O-free; a single environment keeps
    // the run under a second, which is the difference between running the tests
    // and meaning to.
    environment: "node",
  },
});
