import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { PermissionConfig } from "../src/config.ts";
import { DEFAULT_CONFIG } from "../src/config.ts";
import { compileSandboxConfig, expandPatternForLinuxSandbox } from "../src/sandbox-config.ts";

function tempProject() {
	const root = mkdtempSync(join(tmpdir(), "pi-sandbox-config-"));
	mkdirSync(join(root, "workspace"));
	return { root, cwd: join(root, "workspace") };
}

function config(overrides: Partial<PermissionConfig>): PermissionConfig {
	return { ...structuredClone(DEFAULT_CONFIG), rules: [], network: {}, ...overrides } as PermissionConfig;
}

test("linux sandbox expands trailing double-star to existing containing directory", () => {
	const { root } = tempProject();
	const dir = join(root, "example");
	mkdirSync(dir);
	const expanded = expandPatternForLinuxSandbox(join(dir, "**"));
	assert.deepEqual(expanded.paths, [dir]);
});

test("linux sandbox skips non-existing paths instead of emitting invalid bwrap mounts", () => {
	const { root } = tempProject();
	const missing = join(root, "missing", "settings.json");
	const expanded = expandPatternForLinuxSandbox(missing);
	assert.deepEqual(expanded.paths, []);
	assert.match(expanded.warning ?? "", /does not exist/);
});

test("linux sandbox expands existing non-recursive globs", () => {
	const { root } = tempProject();
	writeFileSync(join(root, "a.key"), "a");
	writeFileSync(join(root, "b.txt"), "b");
	const expanded = expandPatternForLinuxSandbox(join(root, "*.key"));
	assert.deepEqual(expanded.paths, [join(root, "a.key")]);
});

test("sandbox config maps deny/read/write rules", () => {
	const { root, cwd } = tempProject();
	const app = join(root, "myapp");
	mkdirSync(app);
	writeFileSync(join(app, "settings.json"), "{}");
	writeFileSync(join(app, "token.txt"), "secret");
	const c = config({
		defaultOutsideCwd: "ask",
		rules: [
			{ path: ".", access: "write", source: "default" },
			{ path: join(app, "**"), access: "deny", source: "global" },
			{ path: join(app, "settings.json"), access: "read", source: "global" },
		],
	});
	const compiled = compileSandboxConfig(c, cwd, "linux").config.filesystem;
	assert.ok(compiled.allowWrite.includes(cwd));
	assert.ok(compiled.denyRead.includes(join(app, "token.txt")));
	assert.ok(compiled.denyRead.every((p) => p !== join(app, "settings.json")));
	assert.ok(compiled.denyWrite.includes(app));
	assert.ok(compiled.allowRead.includes(join(app, "settings.json")));
	assert.ok(compiled.denyWrite.includes(join(app, "settings.json")));
});

test("sandbox config does not expand ordinary recursive denies", () => {
	const { root, cwd } = tempProject();
	const app = join(root, "myapp");
	mkdirSync(join(app, "nested"), { recursive: true });
	writeFileSync(join(app, "nested", "secret.txt"), "secret");
	const c = config({ rules: [{ path: join(app, "**"), access: "deny", source: "global" }] });
	const compiled = compileSandboxConfig(c, cwd, "linux").config.filesystem;
	assert.ok(compiled.denyRead.includes(app));
	assert.equal(compiled.denyRead.includes(join(app, "nested", "secret.txt")), false);
});

test("sandbox config avoids invalid .git/hooks mounts when .git is a file", () => {
	const { cwd } = tempProject();
	mkdirSync(join(cwd, "src"));
	writeFileSync(join(cwd, ".git"), "gitdir: /tmp/not-here");
	writeFileSync(join(cwd, "README.md"), "readme");
	const c = config({ rules: [{ path: ".", access: "write", source: "global" }] });
	const compiled = compileSandboxConfig(c, cwd, "linux");
	assert.equal(compiled.config.filesystem.allowWrite.includes(cwd), false);
	assert.ok(compiled.config.filesystem.allowWrite.includes(join(cwd, "src")));
	assert.ok(compiled.config.filesystem.allowWrite.includes(join(cwd, "README.md")));
	assert.match(compiled.warnings.join("\n"), /\.git is not a directory/);
});

test("default outside cwd ask denies common outside roots for bash", () => {
	const { cwd } = tempProject();
	const c = config({ defaultOutsideCwd: "ask", rules: [{ path: ".", access: "write", source: "default" }] });
	const compiled = compileSandboxConfig(c, cwd, "linux").config.filesystem;
	if (process.platform === "linux") assert.ok(compiled.denyRead.includes("/boot"));
});

test("explicit allow rule carves out one outside file without exposing siblings", (t) => {
	if (!existsSync("/boot/grub/grubenv") || !existsSync("/boot/grub/grub.cfg")) {
		t.skip("requires /boot/grub/grubenv and /boot/grub/grub.cfg on this host");
		return;
	}
	const { cwd } = tempProject();
	const c = config({
		defaultOutsideCwd: "ask",
		rules: [
			{ path: ".", access: "write", source: "default" },
			{ path: "/boot/grub/grubenv", access: "read", source: "global" },
		],
	});
	const compiled = compileSandboxConfig(c, cwd, "linux").config.filesystem;
	assert.equal(compiled.denyRead.includes("/boot"), false);
	assert.equal(compiled.denyRead.includes("/boot/grub"), false);
	assert.equal(compiled.denyRead.includes("/boot/grub/grubenv"), false);
	assert.ok(compiled.denyRead.includes("/boot/grub/grub.cfg"));
});
