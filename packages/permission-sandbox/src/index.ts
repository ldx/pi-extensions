import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { BashOperations, ExtensionAPI, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { createBashTool, getAgentDir } from "@earendil-works/pi-coding-agent";
import { loadPermissionConfig, type Operation, type PermissionConfig } from "./config.ts";
import { evaluatePathPolicy, formatDecision, GrantStore, type PolicyDecision } from "./policy.ts";
import { resolvePathForPolicy } from "./paths.ts";
import { compileSandboxConfig, type SandboxRuntimeLikeConfig } from "./sandbox-config.ts";
import { wrapCommandWithLinuxBwrap } from "./linux-bwrap.ts";

const EXTENSION_NAME = "permission-sandbox";

interface AuditEvent {
	timestamp: string;
	source: "direct-tool";
	operation: Operation;
	path: string;
	reason: string;
}

interface RuntimeState {
	cwd: string;
	config: PermissionConfig;
	configWarnings: string[];
	sandboxWarnings: string[];
	sandboxEnabled: boolean;
	sandboxInitialized: boolean;
	grants: GrantStore;
	audit: AuditEvent[];
}

function initialState(): RuntimeState {
	const loaded = loadPermissionConfig(process.cwd(), getAgentDir());
	return {
		cwd: process.cwd(),
		config: loaded.config,
		configWarnings: loaded.warnings,
		sandboxWarnings: [],
		sandboxEnabled: false,
		sandboxInitialized: false,
		grants: new GrantStore(),
		audit: [],
	};
}

function toolPathAndOperation(event: ToolCallEvent): { path?: string; operation: Operation } | undefined {
	switch (event.toolName) {
		case "read":
			return { path: (event.input as { path?: string }).path, operation: "read" };
		case "write":
		case "edit":
			return { path: (event.input as { path?: string }).path, operation: "write" };
		case "grep":
			return { path: (event.input as { path?: string }).path ?? ".", operation: "read" };
		case "ls":
		case "find":
			return { path: (event.input as { path?: string }).path ?? ".", operation: "list" };
		default:
			return undefined;
	}
}

function appendAudit(pi: ExtensionAPI, state: RuntimeState, decision: PolicyDecision, final: "allow" | "block") {
	const timestamp = new Date().toISOString();
	if (final === "block") {
		state.audit.push({
			timestamp,
			source: "direct-tool",
			operation: decision.operation,
			path: decision.path.canonical,
			reason: decision.reason,
		});
	}
	try {
		pi.appendEntry(EXTENSION_NAME, {
			timestamp,
			final,
			decision: decision.kind,
			operation: decision.operation,
			path: decision.path.canonical,
			reason: decision.reason,
			rule: decision.rule ? { path: decision.rule.path, access: decision.rule.access, source: decision.rule.source } : undefined,
		});
	} catch {
		// Auditing must never break tool execution.
	}
}

function getPersistedDeniedAudits(ctx: ExtensionContext): AuditEvent[] {
	const events: AuditEvent[] = [];
	for (const entry of ctx.sessionManager.getEntries()) {
		if (entry.type !== "custom" || entry.customType !== EXTENSION_NAME) continue;
		const data = entry.data as Partial<{
			timestamp: string;
			final: "allow" | "block";
			operation: Operation;
			path: string;
			reason: string;
		}>;
		if (data.final !== "block" || !data.operation || !data.path) continue;
		events.push({
			timestamp: data.timestamp ?? entry.timestamp,
			source: "direct-tool",
			operation: data.operation,
			path: data.path,
			reason: data.reason ?? "blocked by permission policy",
		});
	}
	return events;
}

function mergeAuditEvents(memory: AuditEvent[], persisted: AuditEvent[]): AuditEvent[] {
	const merged: AuditEvent[] = [];
	const seen = new Set<string>();
	for (const event of [...persisted, ...memory]) {
		const key = `${event.timestamp}\0${event.operation}\0${event.path}\0${event.reason}`;
		if (seen.has(key)) continue;
		seen.add(key);
		merged.push(event);
	}
	return merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

function sanitizeBashEnv(env: NodeJS.ProcessEnv | undefined): NodeJS.ProcessEnv {
	const source = env ?? process.env;
	const keep = new Set([
		"HOME",
		"USER",
		"LOGNAME",
		"SHELL",
		"TERM",
		"COLORTERM",
		"PATH",
		"PWD",
		"TMPDIR",
		"LANG",
		"LC_ALL",
		"LC_CTYPE",
		"DBUS_SESSION_BUS_ADDRESS",
		"XDG_RUNTIME_DIR",
	]);
	const sanitized: NodeJS.ProcessEnv = {};
	for (const key of keep) {
		if (source[key] !== undefined) sanitized[key] = source[key];
	}
	for (const [key, value] of Object.entries(source)) {
		if (value === undefined) continue;
		if (/^(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|no_proxy)$/.test(key)) sanitized[key] = value;
		if (/^(CLAUDE_CODE_HOST_|SANDBOX_RUNTIME$)/.test(key)) sanitized[key] = value;
	}
	return sanitized;
}

async function askForDecision(ctx: ExtensionContext, state: RuntimeState, decision: PolicyDecision): Promise<"allow" | "block"> {
	if (!ctx.hasUI) return state.config.noUiDefault === "allow" ? "allow" : "block";

	const choice = await ctx.ui.select(
		`Permission required\n\n${decision.operation}: ${decision.path.canonical}\n${decision.reason}\n\nAllow this access?`,
		["Allow once", "Allow session path", "Allow session directory", "Block"],
	);

	if (choice === "Allow once") return "allow";
	if (choice === "Allow session path") {
		state.grants.allow(decision.operation, decision.path.canonical, false);
		return "allow";
	}
	if (choice === "Allow session directory") {
		const grantPath = decision.path.exists ? decision.path.canonical : dirname(decision.path.canonical);
		state.grants.allow(decision.operation, grantPath, true);
		return "allow";
	}
	return "block";
}

async function enforceDirectFileTool(pi: ExtensionAPI, event: ToolCallEvent, ctx: ExtensionContext, state: RuntimeState) {
	const target = toolPathAndOperation(event);
	if (!target || !state.config.enabled) return undefined;

	const decision = evaluatePathPolicy({
		config: state.config,
		cwd: state.cwd,
		operation: target.operation,
		path: target.path,
		grants: state.grants,
	});

	if (decision.kind === "allow") {
		appendAudit(pi, state, decision, "allow");
		return undefined;
	}
	if (decision.kind === "block") {
		appendAudit(pi, state, decision, "block");
		return { block: true, reason: formatDecision(decision) };
	}

	const final = await askForDecision(ctx, state, decision);
	appendAudit(pi, state, decision, final);
	if (final === "allow") return undefined;
	return { block: true, reason: `Blocked by permission policy: ${formatDecision(decision)}` };
}

function createSandboxedBashOps(state: RuntimeState): BashOperations {
	return {
		async exec(command, cwd, { onData, signal, timeout, env }) {
			if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);
			const wrappedCommand = process.platform === "linux"
				? wrapCommandWithLinuxBwrap(command, compileSandboxConfig(state.config, state.cwd, "linux").config).command
				: await SandboxManager.wrapWithSandbox(command);
			const scriptPath = join(mkdtempSync(join(tmpdir(), "pi-permission-sandbox-")), "run.sh");
			writeFileSync(scriptPath, `#!/usr/bin/env bash\nexec ${wrappedCommand}\n`, { mode: 0o700 });

			return new Promise((resolve, reject) => {
				const child = spawn("bash", [scriptPath], {
					cwd,
					detached: true,
					stdio: ["ignore", "pipe", "pipe"],
					// The parent pi environment can be very large (mise diffs, long PATH,
					// color tables, proxy state). Combined with a bwrap command containing
					// many mount arguments, that can exceed execve ARG_MAX and produce
					// `spawn E2BIG` before the command even runs. Keep only shell essentials.
					env: sanitizeBashEnv(env),
				});

				let timedOut = false;
				let timeoutHandle: NodeJS.Timeout | undefined;

				if (timeout !== undefined && timeout > 0) {
					timeoutHandle = setTimeout(() => {
						timedOut = true;
						if (child.pid) {
							try {
								process.kill(-child.pid, "SIGKILL");
							} catch {
								child.kill("SIGKILL");
							}
						}
					}, timeout * 1000);
				}

				const handleData = (data: Buffer) => {
					onData(data);
				};
				child.stdout?.on("data", handleData);
				child.stderr?.on("data", handleData);
				child.on("error", (err) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					reject(err);
				});

				const onAbort = () => {
					if (child.pid) {
						try {
							process.kill(-child.pid, "SIGKILL");
						} catch {
							child.kill("SIGKILL");
						}
					}
				};
				signal?.addEventListener("abort", onAbort, { once: true });

				child.on("close", (code) => {
					try {
						rmSync(dirname(scriptPath), { recursive: true, force: true });
					} catch {
						// Best effort cleanup.
					}
					if (timeoutHandle) clearTimeout(timeoutHandle);
					signal?.removeEventListener("abort", onAbort);
					if (signal?.aborted) reject(new Error("aborted"));
					else if (timedOut) reject(new Error(`timeout:${timeout}`));
					else resolve({ exitCode: code });
				});
			});
		},
	};
}

function hasLinuxBwrapDependencies(): boolean {
	return spawnSync("bash", ["-lc", "command -v bwrap >/dev/null"], { stdio: "ignore" }).status === 0;
}

async function initializeSandbox(state: RuntimeState, ctx: ExtensionContext) {
	state.sandboxEnabled = false;
	state.sandboxInitialized = false;
	state.sandboxWarnings = [];

	if (!state.config.enabled || !state.config.sandboxBash) return;
	if (process.platform !== "linux" && process.platform !== "darwin") {
		ctx.ui.notify(`Permission sandbox: bash sandboxing is not supported on ${process.platform}`, "warning");
		return;
	}

	const compiled = compileSandboxConfig(state.config, state.cwd);
	state.sandboxWarnings = compiled.warnings;
	for (const warning of compiled.warnings) ctx.ui.notify(`Permission sandbox: ${warning}`, "warning");

	try {
		if (process.platform === "linux") {
			if (!hasLinuxBwrapDependencies()) throw new Error("bwrap is not installed");
			const planned = wrapCommandWithLinuxBwrap("true", compiled.config as SandboxRuntimeLikeConfig);
			for (const warning of planned.warnings) ctx.ui.notify(`Permission sandbox: ${warning}`, "warning");
			state.sandboxWarnings.push(...planned.warnings);
			state.sandboxEnabled = true;
			state.sandboxInitialized = true;
			return;
		}
		await SandboxManager.reset();
		await SandboxManager.initialize(compiled.config as SandboxRuntimeConfig);
		state.sandboxEnabled = true;
		state.sandboxInitialized = true;
	} catch (err) {
		ctx.ui.notify(`Permission sandbox initialization failed: ${err instanceof Error ? err.message : String(err)}`, "error");
	}
}

export default function permissionSandbox(pi: ExtensionAPI) {
	const state = initialState();
	const placeholderBash = createBashTool(process.cwd());

	pi.registerFlag("no-permission-sandbox", {
		description: "Disable permission-sandbox extension enforcement for this run",
		type: "boolean",
		default: false,
	});

	pi.registerTool({
		...placeholderBash,
		label: "bash (permission sandbox)",
		async execute(id, params, signal, onUpdate) {
			if (!state.config.enabled || !state.config.sandboxBash) {
				return createBashTool(state.cwd).execute(id, params, signal, onUpdate);
			}
			if (!state.sandboxEnabled || !state.sandboxInitialized) {
				if (state.config.sandboxUnavailable === "allow") {
					return createBashTool(state.cwd).execute(id, params, signal, onUpdate);
				}
				throw new Error("Permission sandbox unavailable; bash command blocked");
			}
			return createBashTool(state.cwd, { operations: createSandboxedBashOps(state) }).execute(id, params, signal, onUpdate);
		},
	});

	pi.on("tool_call", async (event, ctx) => {
		if (pi.getFlag("no-permission-sandbox")) return undefined;
		return enforceDirectFileTool(pi, event, ctx, state);
	});

	pi.on("user_bash", () => {
		if (!state.config.enabled || !state.config.sandboxBash) return undefined;
		if (state.sandboxEnabled && state.sandboxInitialized) return { operations: createSandboxedBashOps(state) };
		if (state.config.sandboxUnavailable === "allow") return undefined;
		return {
			result: {
				output: "Permission sandbox unavailable; bash command blocked\n",
				exitCode: 1,
				cancelled: false,
				truncated: false,
			},
		};
	});

	pi.on("session_start", async (_event, ctx) => {
		state.cwd = ctx.cwd;
		state.grants.clear();
		state.audit = [];
		const loaded = loadPermissionConfig(ctx.cwd, getAgentDir());
		state.config = loaded.config;
		state.configWarnings = loaded.warnings;

		if (pi.getFlag("no-permission-sandbox")) {
			state.config.enabled = false;
			ctx.ui.notify("Permission sandbox disabled by --no-permission-sandbox", "warning");
			return;
		}

		for (const warning of loaded.warnings) ctx.ui.notify(`Permission sandbox: ${warning}`, "warning");
		await initializeSandbox(state, ctx);
	});

	pi.on("session_shutdown", async () => {
		if (state.sandboxInitialized) {
			try {
				await SandboxManager.reset();
			} catch {
				// Best effort cleanup.
			}
		}
	});

	pi.registerCommand("permissions", {
		description: "Show permission sandbox status. Use: /permissions rules or /permissions audit",
		handler: async (args, ctx) => {
			const subcommand = args.trim().toLowerCase();
			const loaded = loadPermissionConfig(ctx.cwd, getAgentDir());

			if (subcommand === "rules") {
				const lines = ["Permission rules:"];
				state.config.rules.forEach((rule, index) => {
					const ops = rule.ops?.length ? ` ops=${rule.ops.join(",")}` : "";
					const source = rule.source ? ` source=${rule.source}` : "";
					const comment = rule.comment ? ` -- ${rule.comment}` : "";
					lines.push(`${index + 1}. ${rule.access.padEnd(5)} ${rule.path}${ops}${source}${comment}`);
				});
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}

			if (subcommand === "audit") {
				const denied = mergeAuditEvents(state.audit, getPersistedDeniedAudits(ctx));
				const lines = denied.length === 0
					? ["Permission audit: no direct pi tool denials recorded in this session."]
					: ["Permission audit: direct pi tool denials in this session:"];
				denied.forEach((event, index) => {
					lines.push(`${index + 1}. ${event.timestamp} ${event.operation} ${event.path} -- ${event.reason}`);
				});
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}

			const sampleCwd = resolvePathForPolicy(ctx.cwd, ctx.cwd).canonical;
			const compiled = compileSandboxConfig(state.config, ctx.cwd);
			const fs = compiled.config.filesystem;
			const lines = [
				"Permission sandbox",
				`  enabled: ${state.config.enabled}`,
				`  bash sandbox: ${state.sandboxEnabled ? "enabled" : "disabled"}`,
				`  cwd: ${sampleCwd}`,
				`  global config: ${loaded.globalPath}`,
				`  project config: ${loaded.projectPath}`,
				`  default outside cwd: ${state.config.defaultOutsideCwd}`,
				`  no UI default: ${state.config.noUiDefault}`,
				`  trust project config: ${state.config.trustProjectConfig}`,
				`  rules: ${state.config.rules.length}`,
				`  session grants: ${state.grants.list().length}`,
				`  session denied audit entries: ${state.audit.length}`,
				`  compiled bash policy: writable paths ${fs.allowWrite.length}, read-deny paths ${fs.denyRead.length}, write-deny paths ${fs.denyWrite.length}`,
			];
			if (subcommand && subcommand !== "status") lines.push("", `Unknown subcommand: ${subcommand}`, "Use /permissions, /permissions rules, or /permissions audit.");
			if (state.configWarnings.length > 0) lines.push("", "Config warnings:", ...state.configWarnings.map((w) => `  ${w}`));
			const allSandboxWarnings = [...state.sandboxWarnings, ...compiled.warnings].filter((warning, index, arr) => arr.indexOf(warning) === index);
			if (allSandboxWarnings.length > 0) lines.push("", "Sandbox warnings:", ...allSandboxWarnings.map((w) => `  ${w}`));
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
