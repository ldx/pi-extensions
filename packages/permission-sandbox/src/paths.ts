import { existsSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { expandUser } from "./config.ts";

export interface ResolvedPath {
	input: string;
	absolute: string;
	canonical: string;
	exists: boolean;
	nearestExistingParent: string;
}

export function resolvePathForPolicy(input: string | undefined, cwd: string): ResolvedPath {
	const raw = input && input.length > 0 ? input : ".";
	const expanded = expandUser(raw);
	const absolute = resolve(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
	if (existsSync(absolute)) {
		const canonical = realpathSync(absolute);
		return { input: raw, absolute, canonical, exists: true, nearestExistingParent: canonical };
	}

	let parent = dirname(absolute);
	const missingParts: string[] = [];
	while (!existsSync(parent)) {
		const next = dirname(parent);
		missingParts.unshift(parent.slice(next.length + (next.endsWith(sep) ? 0 : 1)));
		if (next === parent) break;
		parent = next;
	}
	const realParent = existsSync(parent) ? realpathSync(parent) : parent;
	const tail = relative(parent, absolute);
	const canonical = tail ? resolve(realParent, tail) : realParent;
	return { input: raw, absolute, canonical, exists: false, nearestExistingParent: realParent };
}

export function isInsidePath(parent: string, child: string): boolean {
	const rel = relative(parent, child);
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export function normalizeForMatch(path: string): string {
	return path.replace(/\\/g, "/").replace(/\/+$/, "") || "/";
}

function escapeRegex(char: string): string {
	return /[\\^$+?.()|{}[\]]/.test(char) ? `\\${char}` : char;
}

export function hasGlob(pattern: string): boolean {
	return /[*?[]/.test(pattern);
}

export function globToRegex(pattern: string): RegExp {
	const normalized = normalizeForMatch(pattern);
	let out = "^";
	for (let i = 0; i < normalized.length; i++) {
		const ch = normalized[i];
		const next = normalized[i + 1];
		if (ch === "*" && next === "*") {
			const after = normalized[i + 2];
			if (after === "/") {
				out += "(?:.*?/)?";
				i += 2;
			} else {
				out += ".*";
				i += 1;
			}
		} else if (ch === "*") {
			out += "[^/]*";
		} else if (ch === "?") {
			out += "[^/]";
		} else {
			out += escapeRegex(ch);
		}
	}
	out += "$";
	return new RegExp(out);
}

export function pathMatchesPattern(canonicalPath: string, absolutePattern: string): boolean {
	const path = normalizeForMatch(canonicalPath);
	const pattern = normalizeForMatch(absolutePattern);
	if (hasGlob(pattern)) return globToRegex(pattern).test(path);
	return path === pattern || path.startsWith(pattern + "/");
}

export function patternSpecificity(absolutePattern: string): number {
	const normalized = normalizeForMatch(absolutePattern);
	return normalized.replace(/[*?\[\]]/g, "").length;
}
