/**
 * `owlwarden` as a library.
 *
 * Exported so a build script can run a scan without spawning a process. The
 * report format lives in `@dointhai/owlwarden-sdk`; this package only adds the CLI's
 * behaviour on top of it.
 */
export { run, type Streams } from "./run.js";
export { EXIT } from "./exit.js";
export { loadNative, NativeLoadError, type NativeEngine } from "./native.js";
export { parse, ArgError, type Cli, type ScanOptions } from "./args.js";
