import { existsSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import type { SandboxRuntimeLikeConfig } from "./sandbox-config.ts";
import { isInsidePath } from "./paths.ts";

export interface LinuxBwrapPlan {
	command: string;
	warnings: string[];
}

function shQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

function quoteCommand(args: string[]): string {
	return args.map(shQuote).join(" ");
}

function uniqueExisting(paths: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const path of paths) {
		const normalized = resolve(path);
		if (seen.has(normalized) || !existsSync(normalized)) continue;
		seen.add(normalized);
		out.push(normalized);
	}
	return out;
}

function shellPath(): string {
	const candidate = process.env.SHELL;
	if (candidate && candidate.startsWith("/") && existsSync(candidate)) return candidate;
	const found = spawnSync("bash", ["-lc", "command -v bash"], { encoding: "utf8" });
	if (found.status === 0) return found.stdout.trim();
	return "/bin/bash";
}

function isUnderAny(path: string, roots: string[]): boolean {
	return roots.some((root) => path === root || isInsidePath(root, path));
}

function addReadDeny(args: string[], path: string): void {
	const st = statSync(path);
	if (st.isDirectory()) args.push("--tmpfs", path);
	else args.push("--ro-bind", "/dev/null", path);
}

export function wrapCommandWithLinuxBwrap(command: string, config: SandboxRuntimeLikeConfig): LinuxBwrapPlan {
	const warnings: string[] = [];
	const allowWrite = uniqueExisting(config.filesystem.allowWrite);
	const denyWrite = uniqueExisting(config.filesystem.denyWrite);
	const denyRead = uniqueExisting(config.filesystem.denyRead);

	const args = ["bwrap", "--new-session", "--die-with-parent", "--ro-bind", "/", "/"];

	const allowedDomains = config.network?.allowedDomains;
	const deniedDomains = config.network?.deniedDomains;
	if (Array.isArray(allowedDomains) && allowedDomains.length === 0) {
		args.push("--unshare-net");
	} else if ((allowedDomains && allowedDomains.length > 0) || (deniedDomains && deniedDomains.length > 0)) {
		warnings.push("Linux bwrap fallback does not enforce domain-level network rules; filesystem sandboxing is still active.");
	}

	for (const path of allowWrite) {
		args.push("--bind", path, path);
	}

	for (const path of denyWrite) {
		if (!isUnderAny(path, allowWrite)) continue;
		args.push("--ro-bind", path, path);
	}

	for (const path of denyRead) {
		addReadDeny(args, path);
	}

	args.push("--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--", shellPath(), "-c", command);
	return { command: quoteCommand(args), warnings };
}
