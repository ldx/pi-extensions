# pi-extensions

A monorepo of Pi coding agent extensions.

## Packages

- [`packages/permission-sandbox`](packages/permission-sandbox) -- permission checks for Pi file tools plus sandboxed bash via `@anthropic-ai/sandbox-runtime`.
- [`packages/context-usage`](packages/context-usage) -- `/context-usage` with categorized context-window usage estimates.
- [`packages/handoff`](packages/handoff) -- `/handoff` to summarize the current context into a fresh focused session.
- [`packages/tools`](packages/tools) -- `/tools` to inspect and toggle active tools.

## Development

```bash
npm install
npm test
```

## Security

Extensions run with the user's local permissions. Review code carefully before installing or enabling an extension.
