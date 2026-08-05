/**
 * `@dointhai/owlwarden-config` — where a scan's settings come from.
 *
 * Precedence, highest first: command-line flags, the config file, the defaults.
 * The CLI applies the first of those; this package owns the other two.
 */
export {
  configSchema,
  defineConfig,
  ruleOverrideSchema,
  type OwlwardenConfig,
  type OwlwardenConfigInput,
} from "./schema.js";

export {
  CONFIG_FILES,
  formatConfigError,
  resolveConfig,
  type ConfigError,
  type ConfigResult,
  type ConfigSource,
} from "./resolve.js";
