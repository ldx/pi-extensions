import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { DEFAULT_CONFIG, type PermissionConfig } from "../src/config.ts";
import { compileSandboxConfig } from "../src/sandbox-config.ts";

const hasBwrap = spawnSync("bash", ["-lc", "command -v bwrap >/dev/null"]).status === 0;
const insideSandboxRuntime = process.env.SANDBOX_RUNTIME === "1" || process.env.PI_CODING_AGENT === "true";
const skipSandboxRuntimeIntegration = insideSandboxRuntime || process.env.CI === "true";

function shQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

async function runSandboxed(command: string, cwd: string) {
	const wrapped = await SandboxManager.wrapWithSandbox(command);
	return spawnSync("bash", ["-c", wrapped], { cwd, encoding: "utf8" });
}

test("sandbox-runtime allows read carveout under denied directory", { skip: process.platform !== "linux" || !hasBwrap || skipSandboxRuntimeIntegration }, async () => {
	const root = mkdtempSync(join(tmpdir(), "pi-srt-"));
	const cwd = join(root, "workspace");
	const app = join(root, "myapp");
	mkdirSync(cwd);
	mkdirSync(app);
	const settings = join(app, "settings.json");
	const token = join(app, "token.txt");
	writeFileSync(settings, "settings-ok");
	writeFileSync(token, "token-secret");

	const permissionConfig: PermissionConfig = {
		...structuredClone(DEFAULT_CONFIG),
		network: { allowedDomains: [], deniedDomains: [] },
		rules: [
			{ path: ".", access: "write", source: "default" },
			{ path: join(app, "**"), access: "deny", source: "global" },
			{ path: settings, access: "read", source: "global" },
		],
	};
	const sandboxConfig = compileSandboxConfig(permissionConfig, cwd, "linux").config;
	delete sandboxConfig.network; // Integration tests exercise filesystem policy only.

	await SandboxManager.reset();
	await SandboxManager.initialize(sandboxConfig);

	try {
		const allowed = await runSandboxed(`cat ${shQuote(settings)}`, cwd);
		assert.equal(allowed.status, 0, allowed.stderr);
		assert.match(allowed.stdout, /settings-ok/);

		const denied = await runSandboxed(`cat ${shQuote(token)}`, cwd);
		assert.notEqual(denied.status, 0, "denied file should not be readable");
	} finally {
		await SandboxManager.reset();
	}
});

test("sandbox-runtime blocks writes outside allowWrite", { skip: process.platform !== "linux" || !hasBwrap || skipSandboxRuntimeIntegration }, async () => {
	const root = mkdtempSync(join(tmpdir(), "pi-srt-write-"));
	const cwd = join(root, "workspace");
	const app = join(root, "myapp");
	mkdirSync(cwd);
	mkdirSync(app);

	await SandboxManager.reset();
	await SandboxManager.initialize({
		filesystem: {
			denyRead: [],
			allowRead: [cwd, app],
			allowWrite: [cwd],
			denyWrite: [app],
		},
	});

	try {
		const inWorkspace = await runSandboxed("printf ok > created.txt && cat created.txt", cwd);
		assert.equal(inWorkspace.status, 0, inWorkspace.stderr);
		assert.match(inWorkspace.stdout, /ok/);

		const denied = await runSandboxed(`printf nope > ${shQuote(join(app, "created.txt"))}`, cwd);
		assert.notEqual(denied.status, 0, "write outside allowWrite should fail");
	} finally {
		await SandboxManager.reset();
	}
});
