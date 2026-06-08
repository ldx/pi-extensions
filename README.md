# pi-extensions

A monorepo of Pi coding agent extensions.

## Packages

- [`packages/permission-sandbox`](packages/permission-sandbox) -- permission checks for Pi file tools plus sandboxed bash via `@anthropic-ai/sandbox-runtime`.

## Development

```bash
npm install
npm test
```

## Security

Extensions run with the user's local permissions. Review code carefully before installing or enabling an extension.
