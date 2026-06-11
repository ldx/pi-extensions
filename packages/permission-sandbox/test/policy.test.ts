import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { PermissionConfig } from "../src/config.ts";
import { DEFAULT_CONFIG } from "../src/config.ts";
import { evaluatePathPolicy } from "../src/policy.ts";

function tempProject() {
	const root = mkdtempSync(join(tmpdir(), "pi-perms-"));
	mkdirSync(join(root, "workspace"));
	return { root, cwd: join(root, "workspace") };
}

function config(overrides: Partial<PermissionConfig>): PermissionConfig {
	return { ...structuredClone(DEFAULT_CONFIG), rules: [], network: {}, ...overrides } as PermissionConfig;
}

test("inside cwd is writable by default", () => {
	const { cwd } = tempProject();
	const decision = evaluatePathPolicy({ config: config({}), cwd, operation: "write", path: "src/app.ts" });
	assert.equal(decision.kind, "allow");
});

test("outside cwd asks by default", () => {
	const { root, cwd } = tempProject();
	writeFileSync(join(root, "outside.txt"), "x");
	const decision = evaluatePathPolicy({ config: config({}), cwd, operation: "read", path: join(root, "outside.txt") });
	assert.equal(decision.kind, "ask");
});

test("read-only rule allows read and blocks write", () => {
	const { cwd } = tempProject();
	writeFileSync(join(cwd, ".env"), "SECRET=1");
	const c = config({ rules: [{ path: ".env", access: "read", source: "global" }] });
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: ".env" }).kind, "allow");
	const writeDecision = evaluatePathPolicy({ config: c, cwd, operation: "write", path: ".env" });
	assert.equal(writeDecision.kind, "block");
	assert.match(writeDecision.reason, /read-only/);
});

test("specific allow carves out broad deny", () => {
	const { root, cwd } = tempProject();
	const app = join(root, "myapp");
	mkdirSync(app);
	writeFileSync(join(app, "settings.json"), "{}");
	writeFileSync(join(app, "token.txt"), "secret");
	const c = config({
		rules: [
			{ path: join(app, "**"), access: "deny", source: "global" },
			{ path: join(app, "settings.json"), access: "read", source: "global" },
		],
	});
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: join(app, "settings.json") }).kind, "allow");
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "write", path: join(app, "settings.json") }).kind, "block");
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: join(app, "token.txt") }).kind, "block");
});

test("bash-only rule does not allow direct file tools", () => {
	const { root, cwd } = tempProject();
	const cache = join(root, "cache");
	mkdirSync(cache);
	writeFileSync(join(cache, "state.json"), "{}");
	const c = config({ rules: [{ path: join(cache, "**"), access: "write", ops: ["bash"], source: "global" }] });
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: join(cache, "state.json") }).kind, "ask");
});

test("user exact rule can override matching default deny", () => {
	const { root, cwd } = tempProject();
	const hosts = join(root, "hosts.yml");
	writeFileSync(hosts, "token");
	const c = config({
		rules: [
			{ path: hosts, access: "deny", source: "default" },
			{ path: hosts, access: "read", source: "global" },
		],
	});
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: hosts }).kind, "allow");
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "write", path: hosts }).kind, "block");
});

test("untrusted project config cannot allow outside cwd", () => {
	const { root, cwd } = tempProject();
	const outside = join(root, "outside.txt");
	writeFileSync(outside, "x");
	const c = config({
		trustProjectConfig: false,
		rules: [{ path: outside, access: "write", source: "project" }],
	});
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: outside }).kind, "ask");
});

test("trusted project config can allow outside cwd", () => {
	const { root, cwd } = tempProject();
	const outside = join(root, "outside.txt");
	writeFileSync(outside, "x");
	const c = config({
		trustProjectConfig: true,
		rules: [{ path: outside, access: "write", source: "project" }],
	});
	assert.equal(evaluatePathPolicy({ config: c, cwd, operation: "read", path: outside }).kind, "allow");
});

test("reading an ancestor of a denied path is blocked", () => {
	const { cwd } = tempProject();
	mkdirSync(join(cwd, "secrets"));
	writeFileSync(join(cwd, "secrets", "token.txt"), "secret");
	const c = config({ rules: [{ path: "secrets/**", access: "deny", source: "global" }] });
	const decision = evaluatePathPolicy({ config: c, cwd, operation: "read", path: "." });
	assert.equal(decision.kind, "block");
	assert.match(decision.reason, /protected descendant/);
});
