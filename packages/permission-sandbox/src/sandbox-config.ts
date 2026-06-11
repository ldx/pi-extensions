import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { PermissionConfig } from "./config.ts";
import { compileRules, type CompiledRule } from "./policy.ts";
import { globToRegex, hasGlob, isInsidePath, normalizeForMatch, pathMatchesPattern } from "./paths.ts";

export interface SandboxRuntimeLikeConfig {
	network?: PermissionConfig["network"];
	filesystem: {
		denyRead: string[];
		allowRead: string[];
		allowWrite: string[];
		denyWrite: string[];
	};
	ignoreViolations?: Record<string, string[]>;
	enableWeakerNestedSandbox?: boolean;
	enableWeakerNetworkIsolation?: boolean;
}

export interface CompiledSandboxConfig {
	config: SandboxRuntimeLikeConfig;
	warnings: string[];
}

function unique(values: string[]): string[] {
	return [...new Set(values.map((v) => resolve(v)))];
}

function firstGlobIndex(pattern: string): number {
	const indexes = [pattern.indexOf("*"), pattern.indexOf("?"), pattern.indexOf("[")].filter((i) => i >= 0);
	return indexes.length === 0 ? -1 : Math.min(...indexes);
}

function walkExisting(root: string, limit = 5000): string[] {
	const out: string[] = [];
	const stack = [root];
	while (stack.length > 0 && out.length < limit) {
		const current = stack.pop()!;
		out.push(current);
		let st;
		try {
			st = statSync(current);
		} catch {
			continue;
		}
		if (!st.isDirectory()) continue;
		let entries: string[];
		try {
			entries = readdirSync(current);
		} catch {
			continue;
		}
		for (const entry of entries) stack.push(join(current, entry));
	}
	return out;
}

export function expandPatternForLinuxSandbox(absolutePattern: string, mode: "mount" | "deny-read" = "mount"): { paths: string[]; warning?: string } {
	const normalized = normalizeForMatch(absolutePattern);
	if (!hasGlob(normalized)) {
		if (!existsSync(absolutePattern)) {
			return { paths: [], warning: `Sandbox path ${absolutePattern} does not exist; direct pi file tools will still enforce it.` };
		}
		if (mode === "deny-read" && statSync(absolutePattern).isDirectory()) {
			return { paths: walkExisting(absolutePattern).filter((p) => p !== absolutePattern) };
		}
		return { paths: [absolutePattern] };
	}
	if (normalized.endsWith("/**")) {
		const root = normalized.slice(0, -3);
		if (!existsSync(root)) {
			return { paths: [], warning: `Sandbox glob ${absolutePattern} has no existing root ${root}; direct pi file tools will still enforce it.` };
		}
		if (mode === "deny-read") return { paths: walkExisting(root).filter((p) => p !== root) };
		return { paths: [root] };
	}

	const globIndex = firstGlobIndex(normalized);
	const slashBeforeGlob = normalized.lastIndexOf("/", globIndex);
	const root = slashBeforeGlob <= 0 ? "/" : normalized.slice(0, slashBeforeGlob);
	if (!existsSync(root)) {
		return { paths: [], warning: `Sandbox glob ${absolutePattern} has no existing root ${root}; direct pi file tools will still enforce it.` };
	}

	const regex = globToRegex(normalized);
	const matches = walkExisting(root).filter((p) => regex.test(normalizeForMatch(p)));
	if (matches.length === 0) {
		return { paths: [], warning: `Sandbox glob ${absolutePattern} matched no existing paths; direct pi file tools will still enforce it.` };
	}
	return { paths: matches };
}

function sandboxPathsForRule(rule: CompiledRule, platform: NodeJS.Platform, warnings: string[], mode: "mount" | "deny-read" = "mount"): string[] {
	if (platform === "linux") {
		const expanded = expandPatternForLinuxSandbox(rule.absolutePattern, mode);
		// Default protective glob rules such as .env.*, *.pem, and *.key are intentionally
		// opportunistic. They should protect matching files when present without warning
		// on every project where they are absent.
		if (expanded.warning && rule.source !== "default") warnings.push(expanded.warning);
		return expanded.paths;
	}
	return [rule.absolutePattern];
}

function expandAllowedWritePathsForLinux(paths: string[], warnings: string[]): string[] {
	const out: string[] = [];
	for (const allowedPath of paths) {
		const gitPath = join(allowedPath, ".git");
		if (existsSync(gitPath) && !statSync(gitPath).isDirectory()) {
			// sandbox-runtime always adds a mandatory deny for <cwd>/.git/hooks. In git
			// worktrees, .git is a file, so allowing writes to the whole worktree makes
			// bwrap fail while trying to mount below that file. Bind existing children
			// instead. This preserves most write behavior while avoiding the invalid mount.
			warnings.push(`Sandbox write access to ${allowedPath} was expanded to existing children because ${gitPath} is not a directory. New top-level files from bash may be blocked; direct pi write/edit tools are unaffected.`);
			try {
				for (const entry of readdirSync(allowedPath)) {
					if (entry === ".git") continue;
					out.push(join(allowedPath, entry));
				}
			} catch {
				// If listing fails, fall back to omitting this path rather than producing
				// a bwrap invocation known to fail.
			}
			continue;
		}
		out.push(allowedPath);
	}
	return out;
}

function allowOverridesDeny(rule: CompiledRule, denyingRule: CompiledRule): boolean {
	if (rule.specificity > denyingRule.specificity) return true;
	return rule.specificity === denyingRule.specificity && denyingRule.source === "default" && rule.source !== "default";
}

function isReadAllowedByMoreSpecificRule(path: string, denyingRule: CompiledRule, rules: CompiledRule[]): boolean {
	return rules.some((rule) => {
		if (rule === denyingRule) return false;
		if (rule.access !== "read" && rule.access !== "write") return false;
		if (!allowOverridesDeny(rule, denyingRule)) return false;
		return pathMatchesPattern(path, rule.absolutePattern) || isInsidePath(path, rule.absolutePattern);
	});
}

function hasMoreSpecificAllowUnderRule(denyingRule: CompiledRule, rules: CompiledRule[]): boolean {
	return rules.some((rule) => {
		if (rule === denyingRule) return false;
		if (rule.access !== "read" && rule.access !== "write") return false;
		if (!allowOverridesDeny(rule, denyingRule)) return false;
		return pathMatchesPattern(rule.absolutePattern, denyingRule.absolutePattern) || isInsidePath(denyingRule.absolutePattern, rule.absolutePattern);
	});
}

function allowRulesInRoot(root: string, rules: CompiledRule[]): CompiledRule[] {
	return rules.filter((rule) => {
		if (rule.access !== "read" && rule.access !== "write") return false;
		return isInsidePath(root, rule.absolutePattern) || pathMatchesPattern(root, rule.absolutePattern);
	});
}

function isAllowedPathOrAncestor(path: string, allowRules: CompiledRule[]): boolean {
	return allowRules.some((rule) => pathMatchesPattern(path, rule.absolutePattern) || isInsidePath(path, rule.absolutePattern));
}

function denySiblingsExceptAllowed(root: string, allowRules: CompiledRule[]): string[] {
	const denied: string[] = [];
	const visit = (current: string) => {
		let entries: string[];
		try {
			entries = readdirSync(current);
		} catch {
			return;
		}
		for (const entry of entries) {
			const child = join(current, entry);
			const relevantAllows = allowRules.filter((rule) =>
				pathMatchesPattern(child, rule.absolutePattern) || isInsidePath(child, rule.absolutePattern)
			);
			if (relevantAllows.length === 0) {
				denied.push(child);
				continue;
			}
			// If the child itself is fully allowed by an exact/directory rule, do not
			// recurse and do not deny its children. If it is only an ancestor of a
			// narrower allowed path, recurse one level and deny siblings along the way.
			const childIsAllowed = relevantAllows.some((rule) => pathMatchesPattern(child, rule.absolutePattern));
			if (!childIsAllowed && existsSync(child) && statSync(child).isDirectory()) visit(child);
		}
	};
	visit(root);
	return denied;
}

function addDefaultOutsideCwdDenyReadPaths(args: {
	config: PermissionConfig;
	cwd: string;
	platform: NodeJS.Platform;
	rules: CompiledRule[];
	denyRead: string[];
	warnings: string[];
}): void {
	if (args.config.defaultOutsideCwd !== "ask" && args.config.defaultOutsideCwd !== "deny") return;
	if (args.platform !== "linux") return;

	// sandbox-runtime's Linux backend has deny-only read semantics: allowRead is
	// not a real carveout in the generated bwrap mount plan. So do not deny broad
	// ancestors such as / or /home when cwd lives under them. Instead deny common
	// outside-cwd roots that are not needed for normal shell execution. Direct pi
	// file tools still enforce the complete defaultOutsideCwd policy and can ask.
	const commonOutsideRoots = ["/boot", "/root", "/media", "/mnt", "/srv"];
	for (const root of commonOutsideRoots) {
		if (!existsSync(root)) continue;
		if (isInsidePath(root, args.cwd)) continue;
		const allows = allowRulesInRoot(root, args.rules);
		if (allows.length === 0) {
			args.denyRead.push(root);
			continue;
		}
		args.denyRead.push(...denySiblingsExceptAllowed(root, allows));
	}

	const home = process.env.HOME;
	if (home && existsSync(home) && !isInsidePath(home, args.cwd)) {
		try {
			for (const entry of readdirSync(home)) {
				const path = join(home, entry);
				if (isInsidePath(path, args.cwd)) continue;
				if (allowRulesInRoot(path, args.rules).length > 0) continue;
				args.denyRead.push(path);
			}
		} catch (err) {
			args.warnings.push(`Could not enumerate ${home} for outside-cwd bash read denies: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
}

export function compileSandboxConfig(config: PermissionConfig, cwd: string, platform: NodeJS.Platform = process.platform): CompiledSandboxConfig {
	const warnings: string[] = [];
	const rules = compileRules(config, cwd);
	const denyRead: string[] = [];
	const allowRead: string[] = [];
	const allowWrite: string[] = [];
	const denyWrite: string[] = [];

	addDefaultOutsideCwdDenyReadPaths({ config, cwd, platform, rules, denyRead, warnings });

	for (const rule of rules) {
		if (rule.ops?.length && !rule.ops.includes("bash") && !rule.ops.includes("read") && !rule.ops.includes("write")) continue;
		if (platform === "linux" && (rule.absolutePattern === "/dev" || rule.absolutePattern.startsWith("/dev/"))) {
			warnings.push(`Rule ${rule.path} targets /dev. sandbox-runtime mounts /dev for bash compatibility, so direct pi file tools enforce this rule but bash may still see device nodes.`);
		}
		const paths = sandboxPathsForRule(rule, platform, warnings);
		if (paths.length === 0) continue;
		switch (rule.access) {
			case "deny":
			case "ask": {
				// Denying a directory root is enough unless a more-specific allow/read
				// rule needs a carveout beneath it. Expanding every descendant for normal
				// /** deny rules can exceed bubblewrap's argument limit.
				const needsCarveout = platform === "linux" && hasMoreSpecificAllowUnderRule(rule, rules);
				const readDenyPaths = (needsCarveout ? sandboxPathsForRule(rule, platform, warnings, "deny-read") : paths)
					.filter((p) => !isReadAllowedByMoreSpecificRule(p, rule, rules));
				denyRead.push(...readDenyPaths);
				denyWrite.push(...paths);
				break;
			}
			case "read":
				allowRead.push(...paths);
				denyWrite.push(...paths);
				break;
			case "write": {
				const writePaths = platform === "linux" ? expandAllowedWritePathsForLinux(paths, warnings) : paths;
				allowRead.push(...paths);
				allowWrite.push(...writePaths);
				break;
			}
		}
	}

	return {
		config: {
			network: config.network,
			filesystem: {
				denyRead: unique(denyRead),
				allowRead: unique(allowRead),
				allowWrite: unique(allowWrite),
				denyWrite: unique(denyWrite),
			},
			ignoreViolations: config.ignoreViolations,
			enableWeakerNestedSandbox: config.enableWeakerNestedSandbox,
			enableWeakerNetworkIsolation: config.enableWeakerNetworkIsolation,
		},
		warnings,
	};
}
