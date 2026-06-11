import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DEFAULT_CONFIG, type PermissionConfig } from "../src/config.ts";
import { wrapCommandWithLinuxBwrap } from "../src/linux-bwrap.ts";
import { compileSandboxConfig } from "../src/sandbox-config.ts";

test("linux bwrap wrapper does not add sandbox-runtime mandatory cwd placeholders", () => {
	const root = mkdtempSync(join(tmpdir(), "pi-bwrap-plan-"));
	const cwd = join(root, "workspace");
	mkdirSync(cwd);

	const permissionConfig: PermissionConfig = {
		...structuredClone(DEFAULT_CONFIG),
		network: { allowedDomains: [], deniedDomains: [] },
		rules: [
			{ path: cwd, access: "write", source: "global" },
			{ path: join(cwd, ".claude", "commands"), access: "deny", source: "global" },
			{ path: join(cwd, ".bashrc"), access: "deny", source: "global" },
		],
	};

	const sandboxConfig = compileSandboxConfig(permissionConfig, cwd, "linux").config;
	const plan = wrapCommandWithLinuxBwrap("true", sandboxConfig);

	assert.doesNotMatch(plan.command, new RegExp(`${cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/\\.claude/commands`));
	assert.doesNotMatch(plan.command, new RegExp(`${cwd.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/\\.bashrc`));
});
