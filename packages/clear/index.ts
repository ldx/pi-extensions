import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
	pi.registerCommand("clear", {
		description: "Clear context by replacing the current session with a new empty session",
		handler: async (_args, ctx) => {
			await ctx.waitForIdle();

			const currentSessionFile = ctx.sessionManager.getSessionFile();
			const entries = ctx.sessionManager.getBranch().length;

			if (entries === 0) {
				ctx.ui.notify("Context is already clear.", "info");
				return;
			}

			const result = await ctx.newSession({
				parentSession: currentSessionFile,
				withSession: async (replacementCtx) => {
					replacementCtx.ui.setEditorText("");
					replacementCtx.ui.notify("Context cleared. Started a fresh empty session.", "info");
				},
			});

			if (result.cancelled) {
				ctx.ui.notify("Clear cancelled.", "info");
			}
		},
	});
}
