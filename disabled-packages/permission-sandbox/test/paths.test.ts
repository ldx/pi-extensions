import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { globToRegex, isInsidePath, pathMatchesPattern, resolvePathForPolicy } from "../src/paths.ts";

function tempProject() {
	const root = mkdtempSync(join(tmpdir(), "pi-paths-"));
	mkdirSync(join(root, "workspace"));
	return { root, cwd: join(root, "workspace") };
}

test("containment check rejects siblings", () => {
	assert.equal(isInsidePath("/a/b", "/a/b/c"), true);
	assert.equal(isInsidePath("/a/b", "/a/b"), true);
	assert.equal(isInsidePath("/a/b", "/a/bb"), false);
});

test("glob supports double-star carveout patterns", () => {
	const re = globToRegex("/home/me/.config/myapp/**");
	assert.equal(re.test("/home/me/.config/myapp/settings.json"), true);
	assert.equal(re.test("/home/me/.config/other/settings.json"), false);
});

test("path matching handles exact and recursive literal rules", () => {
	assert.equal(pathMatchesPattern("/tmp/a/b", "/tmp/a"), true);
	assert.equal(pathMatchesPattern("/tmp/a", "/tmp/a"), true);
	assert.equal(pathMatchesPattern("/tmp/ab", "/tmp/a"), false);
});

test("symlink targets are canonicalized outside cwd", () => {
	const { root, cwd } = tempProject();
	const outside = join(root, "outside");
	mkdirSync(outside);
	writeFileSync(join(outside, "secret.txt"), "secret");
	symlinkSync(outside, join(cwd, "link"));
	const resolved = resolvePathForPolicy("link/secret.txt", cwd);
	assert.equal(resolved.canonical, join(outside, "secret.txt"));
	assert.equal(isInsidePath(cwd, resolved.canonical), false);
});

test("new files through symlink parents resolve to real target", () => {
	const { root, cwd } = tempProject();
	const outside = join(root, "outside");
	mkdirSync(outside);
	symlinkSync(outside, join(cwd, "link"));
	const resolved = resolvePathForPolicy("link/new.txt", cwd);
	assert.equal(resolved.canonical, join(outside, "new.txt"));
});
