import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

export type Access = "deny" | "ask" | "read" | "write";
export type Operation = "read" | "write" | "list" | "bash";
export type NoUiDefault = "block" | "allow";
export type SandboxUnavailable = "block" | "allow";

export interface PermissionRule {
	path: string;
	access: Access;
	ops?: Operation[];
	comment?: string;
	source?: "default" | "global" | "project" | "session";
}

export interface NetworkConfig {
	allowedDomains?: string[];
	deniedDomains?: string[];
	allowUnixSockets?: string[];
	allowLocalBinding?: boolean;
}

export interface PermissionConfig {
	enabled: boolean;
	sandboxBash: boolean;
	noUiDefault: NoUiDefault;
	sandboxUnavailable: SandboxUnavailable;
	trustProjectConfig: boolean;
	defaultOutsideCwd: Access;
	defaultInsideCwd: Access;
	allowProjectConfigToLoosenOutsideCwd: boolean;
	network: NetworkConfig;
	rules: PermissionRule[];
	ignoreViolations?: Record<string, string[]>;
	enableWeakerNestedSandbox?: boolean;
	enableWeakerNetworkIsolation?: boolean;
}

export interface LoadedConfig {
	config: PermissionConfig;
	globalPath: string;
	projectPath: string;
	warnings: string[];
}

export const DEFAULT_CONFIG: PermissionConfig = {
	enabled: true,
	sandboxBash: true,
	noUiDefault: "block",
	sandboxUnavailable: "block",
	trustProjectConfig: false,
	defaultOutsideCwd: "ask",
	defaultInsideCwd: "write",
	allowProjectConfigToLoosenOutsideCwd: false,
	network: {
		allowedDomains: [
			"github.com",
			"*.github.com",
			"api.github.com",
			"raw.githubusercontent.com",
			"npmjs.org",
			"*.npmjs.org",
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"pypi.org",
			"*.pypi.org",
		],
		deniedDomains: [],
	},
	rules: [
		{ path: ".", access: "write", source: "default", comment: "current workspace" },
		{ path: "/tmp", access: "write", source: "default", comment: "temporary files" },

		// Project-local secret material. Keep these readable only if the user adds a
		// narrower explicit allow/read rule.
		{ path: ".env", access: "deny", source: "default" },
		{ path: ".env.*", access: "deny", source: "default" },
		{ path: "*.pem", access: "deny", source: "default" },
		{ path: "*.key", access: "deny", source: "default" },
		{ path: "*.p12", access: "deny", source: "default" },
		{ path: "*.pfx", access: "deny", source: "default" },
		{ path: "id_rsa", access: "deny", source: "default" },
		{ path: "id_ed25519", access: "deny", source: "default" },

		// Home-directory credentials, tokens, browser profiles, and local secret stores.
		{ path: "~/.ssh/**", access: "deny", source: "default" },
		{ path: "~/.aws/**", access: "deny", source: "default" },
		{ path: "~/.gnupg/**", access: "deny", source: "default" },
		{ path: "~/.kube/**", access: "deny", source: "default" },
		{ path: "~/.azure/**", access: "deny", source: "default" },
		{ path: "~/.config/gcloud/**", access: "deny", source: "default" },
		{ path: "~/.docker/config.json", access: "deny", source: "default" },
		{ path: "~/.npmrc", access: "deny", source: "default" },
		{ path: "~/.pypirc", access: "deny", source: "default" },
		{ path: "~/.netrc", access: "deny", source: "default" },
		{ path: "~/.git-credentials", access: "deny", source: "default" },
		{ path: "~/.config/gh/hosts.yml", access: "deny", source: "default" },
		{ path: "~/.config/sops/age/keys.txt", access: "deny", source: "default" },
		{ path: "~/.age/**", access: "deny", source: "default" },
		{ path: "~/.password-store/**", access: "deny", source: "default" },
		{ path: "~/.local/share/keyrings/**", access: "deny", source: "default" },
		{ path: "~/.pi/agent/auth.json", access: "deny", source: "default" },
		{ path: "~/.pi/agent/sessions/**", access: "deny", source: "default" },
		{ path: "~/.config/google-chrome/**", access: "deny", source: "default" },
		{ path: "~/.config/chromium/**", access: "deny", source: "default" },
		{ path: "~/.config/BraveSoftware/**", access: "deny", source: "default" },
		{ path: "~/.mozilla/firefox/**", access: "deny", source: "default" },

		// System-level secret stores and high-risk host configuration.
		{ path: "/root/**", access: "deny", source: "default" },
		{ path: "/boot/**", access: "deny", source: "default" },
		{ path: "/etc/shadow", access: "deny", source: "default" },
		{ path: "/etc/gshadow", access: "deny", source: "default" },
		{ path: "/etc/sudoers", access: "deny", source: "default" },
		{ path: "/etc/sudoers.d/**", access: "deny", source: "default" },
		{ path: "/etc/ssh/ssh_host_*_key", access: "deny", source: "default" },
		{ path: "/etc/wireguard/**", access: "deny", source: "default" },
		{ path: "/etc/NetworkManager/system-connections/**", access: "deny", source: "default" },
		{ path: "/var/lib/docker/**", access: "deny", source: "default" },
		{ path: "/var/lib/kubelet/**", access: "deny", source: "default" },
		{ path: "/var/log/**", access: "deny", source: "default" },
		{ path: "/proc/*/environ", access: "deny", source: "default" },
		{ path: "/proc/*/cmdline", access: "deny", source: "default" },
		{ path: "/run/user/*/keyring/**", access: "deny", source: "default" },
	],
};

export function getDefaultGlobalConfigPath(agentDir = join(homedir(), ".pi", "agent")): string {
	return join(agentDir, "permissions.json");
}

export function getDefaultProjectConfigPath(cwd: string): string {
	return join(cwd, ".pi", "permissions.json");
}

function readJson(path: string): unknown | undefined {
	if (!existsSync(path)) return undefined;
	return JSON.parse(readFileSync(path, "utf8"));
}

function normalizeRule(rule: PermissionRule, source: PermissionRule["source"]): PermissionRule {
	return { ...rule, source };
}

function mergeConfig(base: PermissionConfig, override: Partial<PermissionConfig>, source: "global" | "project"): PermissionConfig {
	const out: PermissionConfig = {
		...base,
		network: { ...base.network },
		rules: [...base.rules],
	};

	for (const key of [
		"enabled",
		"sandboxBash",
		"noUiDefault",
		"sandboxUnavailable",
		"trustProjectConfig",
		"defaultOutsideCwd",
		"defaultInsideCwd",
		"allowProjectConfigToLoosenOutsideCwd",
		"ignoreViolations",
		"enableWeakerNestedSandbox",
		"enableWeakerNetworkIsolation",
	] as const) {
		if (override[key] !== undefined) (out as Record<string, unknown>)[key] = override[key];
	}

	if (override.network) out.network = { ...out.network, ...override.network };
	if (override.rules) out.rules = [...out.rules, ...override.rules.map((r) => normalizeRule(r, source))];
	return out;
}

export function loadPermissionConfig(cwd: string, agentDir = join(homedir(), ".pi", "agent")): LoadedConfig {
	const globalPath = getDefaultGlobalConfigPath(agentDir);
	const projectPath = getDefaultProjectConfigPath(cwd);
	const warnings: string[] = [];
	let config = structuredClone(DEFAULT_CONFIG) as PermissionConfig;

	for (const rule of config.rules) rule.source = "default";

	try {
		const globalRaw = readJson(globalPath) as Partial<PermissionConfig> | undefined;
		if (globalRaw) config = mergeConfig(config, globalRaw, "global");
	} catch (err) {
		warnings.push(`Could not parse global permission config ${globalPath}: ${err instanceof Error ? err.message : String(err)}`);
	}

	try {
		const projectRaw = readJson(projectPath) as Partial<PermissionConfig> | undefined;
		if (projectRaw) config = mergeConfig(config, projectRaw, "project");
	} catch (err) {
		warnings.push(`Could not parse project permission config ${projectPath}: ${err instanceof Error ? err.message : String(err)}`);
	}

	return { config, globalPath, projectPath, warnings };
}

export function expandUser(path: string): string {
	if (path === "~") return homedir();
	if (path.startsWith("~/")) return join(homedir(), path.slice(2));
	return path;
}

export function configPathToAbsolute(pattern: string, cwd: string): string {
	const expanded = expandUser(pattern);
	if (isAbsolute(expanded)) return resolve(expanded);
	return resolve(cwd, expanded);
}

export function configPathDirectory(pattern: string, cwd: string): string {
	return dirname(configPathToAbsolute(pattern.replace(/[*?{[].*$/, ""), cwd));
}
