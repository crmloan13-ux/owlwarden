import js from "@eslint/js";
import tseslint from "typescript-eslint";

/**
 * ESLint exists here for the rules a type checker cannot express.
 *
 * `tsc --strict` already covers types; duplicating that in lint rules is noise.
 * What is left, and what these configs are for, is the class of mistake that
 * type-checks fine and is still wrong — a floating promise, a swallowed error,
 * an `any` that leaked in from JSON.
 */
export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "crates/**", "target/**", "fixtures/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // Listed explicitly rather than discovered: test files belong to
        // `tsconfig.lint.json`, not to the package build config, and automatic
        // discovery finds the wrong one.
        project: ["./packages/*/tsconfig.json", "./tsconfig.lint.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // A promise nobody awaits is an error nobody sees. Non-negotiable in a
      // tool whose whole job is reporting problems accurately.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",

      // Unused variables are usually a half-finished edit. The underscore
      // prefix is the escape hatch for deliberate ones.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],

      // `catch {}` hides the thing you most want to know about.
      "no-empty": ["error", { allowEmptyCatch: false }],
    },
  },
  {
    // Tests deliberately poke at malformed input, so a few of the strict rules
    // get in the way without catching anything.
    files: ["packages/*/test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
    },
  },
  {
    // Build scripts are plain JavaScript and are not part of a tsconfig, so the
    // type-aware rules have nothing to work from.
    files: ["**/*.mjs", "**/*.js"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: { process: "readonly", console: "readonly", URL: "readonly" },
    },
  },
);
