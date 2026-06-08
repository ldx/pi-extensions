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

- [`packages/permission-sandbox`](packages/permission-sandbox) -- permission checks for Pi file tools plus sandboxed bash via `@anthropic-ai/sandbox-runtime`.
- [`packages/context-usage`](packages/context-usage) -- `/context-usage` with categorized context-window usage estimates.
- [`packages/handoff`](packages/handoff) -- `/handoff` to summarize the current context into a fresh focused session.
- [`packages/tools`](packages/tools) -- `/tools` to inspect and toggle active tools.

## Commands

After install, these commands are available:

```text
/context-usage
/handoff [goal]
/tools
/tools <tool-name>
/tools enable <tool-name...>
/tools disable <tool-name...>
/tools toggle <tool-name...>
/tools reset
/permissions
/permissions rules
/permissions audit
```

## Permission sandbox setup

The permission sandbox uses `@anthropic-ai/sandbox-runtime` for bash sandboxing.

Linux dependencies:

```bash
sudo apt install bubblewrap socat ripgrep
```

macOS uses `sandbox-exec` via sandbox-runtime and does not need bubblewrap.

Global config path:

```text
~/.pi/agent/permissions.json
```

Project config path:

```text
.pi/permissions.json
```

A recommended baseline config is included at:

```text
packages/permission-sandbox/recommended-permissions.json
```

Example:

```json
{
  "defaultOutsideCwd": "ask",
  "noUiDefault": "block",
  "trustProjectConfig": false,
  "sandboxUnavailable": "block",
  "sandboxBash": true,
  "rules": [
    { "path": ".", "access": "write" },
    { "path": "/tmp", "access": "write" },
    { "path": "~/.config/myapp/**", "access": "deny" },
    { "path": "~/.config/myapp/settings.json", "access": "read" }
  ]
}
```

Access values:

- `deny` -- block reads and writes.
- `ask` -- ask for direct Pi file tools; block in bash sandbox.
- `read` -- allow reads, block writes.
- `write` -- allow reads and writes.

## Development

```bash
npm install
npm test
```

## Security

Extensions run with the user's local permissions. Review code carefully before installing or enabling an extension.

The permission sandbox is a guardrail, not a complete sandbox for the whole Pi process. It checks direct Pi file tools and runs bash through OS sandboxing, but other extension code still executes inside the Pi process.
