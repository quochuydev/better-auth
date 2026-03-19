import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { metamask } from ".";

export const metamaskClient = () => {
	return {
		id: "metamask",
		$InferServerPlugin: {} as ReturnType<typeof metamask>,
	} satisfies BetterAuthClientPlugin;
};
