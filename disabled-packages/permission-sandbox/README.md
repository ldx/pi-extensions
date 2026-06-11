# Pi Permission Sandbox

Lightweight pi extension that combines direct file-tool policy checks with OS-level bash sandboxing. Linux uses a direct `bubblewrap` backend; macOS uses `@anthropic-ai/sandbox-runtime`.

## What it enforces

- Direct pi tools: `read`, `write`, `edit`, `ls`, `grep`, and `find` are checked before execution.
- Agent `bash` and user `!` / `!!` commands run through an OS sandbox when available.
- Outside-cwd direct file access asks in UI by default and blocks in non-interactive mode by default.
- Rules support deny, ask, read-only, and write access.

This is not a full sandbox for pi itself. Other extensions can still access the host filesystem from the pi process.

## Config locations

- Global: `~/.pi/agent/permissions.json`
- Project: `<cwd>/.pi/permissions.json`

Global and project config are merged. By default, project config cannot loosen outside-cwd access unless global config sets `trustProjectConfig` or `allowProjectConfigToLoosenOutsideCwd`.

## Recommended baseline

A recommended baseline config is included at `recommended-permissions.json`. Copy it to `~/.pi/agent/permissions.json` if you want an explicit editable copy:

```bash
cp ~/.pi/agent/extensions/permission-sandbox/recommended-permissions.json ~/.pi/agent/permissions.json
```

The extension also includes similar built-in defaults when no config file exists. The baseline denies common home and system secrets such as SSH keys, cloud credentials, kube configs, browser profiles, pi auth/session files, `/boot/**`, `/root/**`, `/etc/shadow`, sudoers, host SSH private keys, Docker/kubelet state, logs, and process environments.

## Example carveout

```json
{
  "enabled": true,
  "sandboxBash": true,
  "defaultOutsideCwd": "ask",
  "noUiDefault": "block",
  "sandboxUnavailable": "block",
  "rules": [
    {
      "path": "~/.config/myapp/**",
      "access": "deny"
    },
    {
      "path": "~/.config/myapp/settings.json",
      "access": "read"
    },
    {
      "path": ".",
      "access": "write"
    },
    {
      "path": "/tmp",
      "access": "write"
    }
  ]
}
```

Access values:

- `deny`: block reads and writes
- `ask`: ask for direct file tools; block in bash sandbox
- `read`: allow reads, block writes
- `write`: allow reads and writes

## Commands and flags

- `/permissions` shows current status, config paths, rule count, and session grants.
- `/permissions on` enables direct file checks and bash sandboxing for the current session.
- `/permissions off` disables direct file checks and bash sandboxing for the current session.
- `--no-permission-sandbox` disables enforcement for a run.

## Platform notes

- Linux requires `bwrap` for bash sandboxing.
- macOS uses `sandbox-exec` via sandbox-runtime.
- If sandbox initialization fails, bash is blocked by default. Set `sandboxUnavailable` to `allow` only if you want fail-open behavior.

## Linux notes

The Linux backend skips non-existing deny paths instead of creating placeholder mount points in the project. Existing denied files and directories are still hidden or made read-only, and direct pi file tools enforce glob rules exactly.

The Linux backend mounts `/dev` for bash compatibility. Direct pi file tools enforce `/dev/...` rules, but bash commands may still see device nodes such as `/dev/null` and `/dev/zero`.

Some local desktop-app integrations do not work inside a `bubblewrap` mount namespace. In particular, 1Password CLI desktop integration may reject `op` even when its config and daemon pid file are writable. Use `/permissions off`, run the trusted `op` command, then `/permissions on` if you need that integration.
