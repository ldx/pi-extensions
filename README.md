# pi-extensions

A monorepo of Pi coding agent extensions.

## Install

Install all extensions from GitHub:

```bash
pi install git:github.com/ldx/pi-extensions
```

Pin a specific tag or commit if you want reproducible installs:

```bash
pi install git:github.com/ldx/pi-extensions@<tag-or-commit>
```

For local development:

```bash
pi install /home/vilmos/src/pi-extensions
```

Reload Pi after installing or updating:

```text
/reload
```

## Packages

- [`packages/context-usage`](packages/context-usage) -- `/context-usage` with categorized context-window usage estimates.
- [`packages/handoff`](packages/handoff) -- `/handoff` to summarize the current context into a fresh focused session.
- [`packages/tools`](packages/tools) -- `/tools` to inspect and toggle active tools.
- [`packages/clear`](packages/clear) -- `/clear` to reset context into a fresh empty session.

## Commands

After install, these commands are available:

```text
/context-usage
/handoff [goal]
/clear
/tools
/tools <tool-name>
/tools enable <tool-name...>
/tools disable <tool-name...>
/tools toggle <tool-name...>
/tools reset
```

## Development

```bash
npm install
npm test
```

## Security

Extensions run with the user's local permissions. Review code carefully before installing or enabling an extension.

Extensions run inside the Pi process and can access local files and credentials with your user permissions.
