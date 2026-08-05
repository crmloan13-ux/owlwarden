# @owlwarden/config

Config schema and resolver for
[owlwarden](https://github.com/suthat/owlwarden). The CLI depends on this; you
normally do not need to install it yourself.

Install it directly only if you want type-checked config:

```bash
npm i -D @owlwarden/config
```

```ts
// owlwarden.config.ts
import { defineConfig } from "@owlwarden/config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
});
```

## Resolution order

`owlwarden.config.ts`, then `.mts`, `.mjs`, `.js`, `.json`, then an `owlwarden`
key in `package.json`, then built-in defaults. Command-line flags override the
file.

The search does not walk up the directory tree. In a monorepo that would mean
picking up a sibling's configuration and scanning with rules the project never
chose, silently — so the working directory is where the config has to be.

## Licence

MIT OR Apache-2.0.
