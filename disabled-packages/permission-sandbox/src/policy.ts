import { existsSync, statSync } from "node:fs";
import type { Access, Operation, PermissionConfig, PermissionRule } from "./config.ts";
import { configPathToAbsolute } from "./config.ts";
import { hasGlob, isInsidePath, pathMatchesPattern, patternSpecificity, resolvePathForPolicy, type ResolvedPath } from "./paths.ts";

export type DecisionKind = "allow" | "ask" | "block";

export interface PolicyDecision {
	kind: DecisionKind;
	operation: Operation;
	path: ResolvedPath;
	access: Access;
	reason: string;
	rule?: CompiledRule;
}

export interface CompiledRule extends PermissionRule {
	absolutePattern: string;
	specificity: number;
}

export interface SessionGrant {
	operation: Operation | "all";
	path: string;
	recursive: boolean;
}

export class GrantStore {
	private grants: SessionGrant[] = [];

	allow(operation: Operation | "all", canonicalPath: string, recursive = false): void {
		this.grants.push({ operation, path: canonicalPath, recursive });
	}

	clear(): void {
		this.grants = [];
	}

	list(): SessionGrant[] {
		return [...this.grants];
	}

	matches(operation: Operation, canonicalPath: string): boolean {
		return this.grants.some((grant) => {
			if (grant.operation !== "all" && grant.operation !== operation) return false;
			return grant.recursive ? isInsidePath(grant.path, canonicalPath) : grant.path === canonicalPath;
		});
	}
}

function accessPrecedence(access: Access): number {
	switch (access) {
		case "deny": return 4;
		case "ask": return 3;
		case "read": return 2;
		case "write": return 1;
	}
}

export function compileRules(config: PermissionConfig, cwd: string): CompiledRule[] {
	return config.rules.map((rule) => {
		const absolutePattern = configPathToAbsolute(rule.path, cwd);
		return {
			...rule,
			absolutePattern,
			specificity: patternSpecificity(absolutePattern),
		};
	});
}

function ruleAppliesToOperation(rule: PermissionRule, operation: Operation): boolean {
	if (!rule.ops || rule.ops.length === 0) return true;
	if (rule.ops.includes(operation)) return true;
	if (operation === "list" && rule.ops.includes("read")) return true;
	return false;
}

function isProjectLooseningOutsideCwd(rule: CompiledRule, config: PermissionConfig, cwdReal: string, path: ResolvedPath): boolean {
	if (rule.source !== "project") return false;
	if (config.trustProjectConfig || config.allowProjectConfigToLoosenOutsideCwd) return false;
	if (isInsidePath(cwdReal, path.canonical)) return false;
	return rule.access === "read" || rule.access === "write";
}

function sourcePrecedence(rule: CompiledRule): number {
	return rule.source === "default" ? 0 : 1;
}

function chooseRule(rules: CompiledRule[]): CompiledRule | undefined {
	return [...rules].sort((a, b) => {
		const bySpecificity = b.specificity - a.specificity;
		if (bySpecificity !== 0) return bySpecificity;
		const bySource = sourcePrecedence(b) - sourcePrecedence(a);
		if (bySource !== 0) return bySource;
		return accessPrecedence(b.access) - accessPrecedence(a.access);
	})[0];
}

function patternBase(absolutePattern: string): string {
	if (!hasGlob(absolutePattern)) return absolutePattern;
	const firstGlob = Math.min(...[absolutePattern.indexOf("*"), absolutePattern.indexOf("?"), absolutePattern.indexOf("[")].filter((i) => i >= 0));
	const slash = absolutePattern.lastIndexOf("/", firstGlob);
	return slash <= 0 ? "/" : absolutePattern.slice(0, slash);
}

function isDirectoryPath(path: ResolvedPath): boolean {
	if (!path.exists || !existsSync(path.canonical)) return false;
	try {
		return statSync(path.canonical).isDirectory();
	} catch {
		return false;
	}
}

function descendantRestriction(path: ResolvedPath, operation: Operation, rules: CompiledRule[]): CompiledRule | undefined {
	if ((operation !== "read" && operation !== "list") || !isDirectoryPath(path)) return undefined;
	const restrictions = rules.filter((rule) => {
		if (rule.access !== "deny" && rule.access !== "ask") return false;
		const base = patternBase(rule.absolutePattern);
		return isInsidePath(path.canonical, base) && base !== path.canonical;
	});
	return chooseRule(restrictions);
}

function decisionFromAccess(access: Access, operation: Operation): Omit<PolicyDecision, "path" | "operation" | "rule"> {
	if (access === "deny") return { kind: "block", access, reason: "path is denied" };
	if (access === "ask") return { kind: "ask", access, reason: "permission required" };
	if (operation === "write" && access === "read") {
		return { kind: "block", access, reason: "path is read-only" };
	}
	return { kind: "allow", access, reason: access === "write" ? "write allowed" : "read allowed" };
}

export function evaluatePathPolicy(args: {
	config: PermissionConfig;
	cwd: string;
	cwdReal?: string;
	operation: Operation;
	path: string | undefined;
	grants?: GrantStore;
}): PolicyDecision {
	const cwdReal = args.cwdReal ?? resolvePathForPolicy(args.cwd, args.cwd).canonical;
	const path = resolvePathForPolicy(args.path, args.cwd);

	if (args.grants?.matches(args.operation, path.canonical)) {
		return {
			kind: "allow",
			operation: args.operation,
			path,
			access: "write",
			reason: "allowed by session grant",
		};
	}

	const compiled = compileRules(args.config, args.cwd);
	let candidates = compiled.filter((rule) =>
		ruleAppliesToOperation(rule, args.operation) && pathMatchesPattern(path.canonical, rule.absolutePattern)
	);

	const ignoredProjectRules = candidates.filter((rule) => isProjectLooseningOutsideCwd(rule, args.config, cwdReal, path));
	if (ignoredProjectRules.length > 0) {
		candidates = candidates.filter((rule) => !ignoredProjectRules.includes(rule));
	}

	const rule = chooseRule(candidates);
	if (rule) {
		const d = decisionFromAccess(rule.access, args.operation);
		if (d.kind !== "allow") {
			return { ...d, operation: args.operation, path, rule, reason: `${d.reason} by ${rule.source ?? "config"} rule ${rule.path}` };
		}
		const descendant = descendantRestriction(path, args.operation, compiled);
		if (descendant) {
			const dd = decisionFromAccess(descendant.access, args.operation);
			return { ...dd, operation: args.operation, path, rule: descendant, reason: `target contains protected descendant from ${descendant.source ?? "config"} rule ${descendant.path}` };
		}
		return { ...d, operation: args.operation, path, rule, reason: `${d.reason} by ${rule.source ?? "config"} rule ${rule.path}` };
	}

	const descendant = descendantRestriction(path, args.operation, compiled);
	if (descendant) {
		const dd = decisionFromAccess(descendant.access, args.operation);
		return { ...dd, operation: args.operation, path, rule: descendant, reason: `target contains protected descendant from ${descendant.source ?? "config"} rule ${descendant.path}` };
	}

	const defaultAccess = isInsidePath(cwdReal, path.canonical) ? args.config.defaultInsideCwd : args.config.defaultOutsideCwd;
	const d = decisionFromAccess(defaultAccess, args.operation);
	return { ...d, operation: args.operation, path, reason: `${d.reason} by ${isInsidePath(cwdReal, path.canonical) ? "inside-cwd" : "outside-cwd"} default` };
}

export function formatDecision(decision: PolicyDecision): string {
	return `${decision.kind.toUpperCase()} ${decision.operation} ${decision.path.canonical}: ${decision.reason}`;
}
