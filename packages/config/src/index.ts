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
  EXECUTABLE_CONFIG_FILES,
  JSON_CONFIG_FILES,
  MAX_CONFIG_BYTES,
  formatConfigError,
  resolveConfig,
  type ConfigError,
  type ConfigResult,
  type ConfigSource,
  type ResolveConfigOptions,
} from "./resolve.js";
