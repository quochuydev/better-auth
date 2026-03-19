import type { BetterAuthPlugin } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { generateId } from "@better-auth/core/utils/id";
import * as z from "zod";
import { APIError } from "../../api";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import type { InferOptionSchema, User } from "../../types";
import { toChecksumAddress } from "../../utils/hashing";
import { isAPIError } from "../../utils/is-api-error";
import { getOrigin } from "../../utils/url";
import { createSIWEMessage, recoverPersonalSignAddress } from "./crypto";
import { METAMASK_ERROR_CODES } from "./error-codes";
import { schema } from "./schema";
import type { MetaMaskAccount } from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		metamask: {
			creator: typeof metamask;
		};
	}
}

export interface MetaMaskPluginOptions {
	/**
	 * The domain shown in the MetaMask sign-in prompt.
	 * Defaults to the origin derived from `baseURL`.
	 */
	domain?: string;
	/**
	 * A human-readable statement shown in the MetaMask sign-in prompt.
	 * @example "I accept the Terms of Service"
	 */
	statement?: string;
	/**
	 * Additional resource URIs to include in the SIWE message.
	 */
	resources?: string[];
	/**
	 * Domain used for generating a placeholder email when no email is provided.
	 * Defaults to the origin derived from `baseURL`.
	 */
	emailDomainName?: string;
	/**
	 * When `true` (default), users can sign in without providing an email.
	 * A placeholder email is generated from the wallet address.
	 * When `false`, an email must be supplied during verification.
	 */
	anonymous?: boolean;
	/**
	 * Custom schema overrides.
	 */
	schema?: InferOptionSchema<typeof schema>;
}

const walletAddressSchema = z
	.string()
	.regex(/^0[xX][a-fA-F0-9]{40}$/i)
	.length(42);

/**
 * Extracts the nonce from an EIP-4361 (SIWE) formatted message.
 */
function extractNonceFromMessage(message: string): string | null {
	const match = message.match(/^Nonce: (.+)$/m);
	return match?.[1]?.trim() ?? null;
}

export const metamask = (options?: MetaMaskPluginOptions) =>
	({
		id: "metamask",
		schema: mergeSchema(schema, options?.schema),
		endpoints: {
			getMetaMaskNonce: createAuthEndpoint(
				"/metamask/nonce",
				{
					method: "POST",
					body: z.object({
						walletAddress: walletAddressSchema,
						chainId: z.number().int().positive().optional().default(1),
					}),
					metadata: {
						openapi: {
							description:
								"Generate a nonce and SIWE-formatted message for MetaMask sign-in",
							responses: {
								200: {
									description: "Nonce and sign-in message generated",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													nonce: { type: "string" },
													message: { type: "string" },
												},
												required: ["nonce", "message"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const { walletAddress: rawAddress, chainId } = ctx.body;
					const walletAddress = toChecksumAddress(rawAddress);
					const nonce = generateId();
					const issuedAt = new Date().toISOString();

					// Store both nonce and issuedAt so the server can reconstruct
					// the exact message during verification.
					await ctx.context.internalAdapter.createVerificationValue({
						identifier: `metamask:${walletAddress}:${chainId}`,
						value: `${nonce}|${issuedAt}`,
						expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
					});

					const domain =
						options?.domain ??
						getOrigin(ctx.context.baseURL) ??
						ctx.context.baseURL;

					const message = createSIWEMessage({
						domain,
						address: walletAddress,
						statement: options?.statement,
						uri: ctx.context.baseURL,
						chainId,
						nonce,
						issuedAt,
						resources: options?.resources,
					});

					return ctx.json({ nonce, message });
				},
			),

			verifyMetaMaskSignature: createAuthEndpoint(
				"/metamask/verify",
				{
					method: "POST",
					body: z
						.object({
							/**
							 * The SIWE message returned by the nonce endpoint.
							 * This is the exact string that MetaMask signed.
							 */
							message: z.string().min(1),
							/**
							 * The hex-encoded EIP-191 signature produced by MetaMask.
							 */
							signature: z.string().min(1),
							walletAddress: walletAddressSchema,
							chainId: z.number().int().positive().optional().default(1),
							email: z.email().optional(),
						})
						.refine(
							(data) => options?.anonymous !== false || !!data.email,
							{
								message:
									"Email is required when the anonymous option is disabled.",
								path: ["email"],
							},
						),
					requireRequest: true,
					metadata: {
						openapi: {
							description:
								"Verify a MetaMask signature and create an authenticated session",
							responses: {
								200: {
									description: "Sign-in successful",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													token: { type: "string" },
													user: { type: "object" },
												},
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const {
						message,
						signature,
						walletAddress: rawAddress,
						chainId,
						email,
					} = ctx.body;
					const walletAddress = toChecksumAddress(rawAddress);
					const isAnon = options?.anonymous ?? true;

					try {
						// 1. Look up the stored verification entry
						const verification =
							await ctx.context.internalAdapter.findVerificationValue(
								`metamask:${walletAddress}:${chainId}`,
							);

						if (!verification || new Date() > verification.expiresAt) {
							throw APIError.from(
								"UNAUTHORIZED",
								METAMASK_ERROR_CODES.INVALID_OR_EXPIRED_NONCE,
							);
						}

						// 2. Verify the nonce in the message matches the stored nonce
						const [storedNonce] = verification.value.split("|");
						const messageNonce = extractNonceFromMessage(message);

						if (!messageNonce || messageNonce !== storedNonce) {
							throw APIError.from(
								"UNAUTHORIZED",
								METAMASK_ERROR_CODES.INVALID_OR_EXPIRED_NONCE,
							);
						}

						// 3. Recover the signer address from the EIP-191 signature
						let recoveredAddress: string;
						try {
							recoveredAddress = recoverPersonalSignAddress(message, signature);
						} catch {
							throw APIError.from(
								"UNAUTHORIZED",
								METAMASK_ERROR_CODES.INVALID_SIGNATURE,
							);
						}

						if (
							recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()
						) {
							throw APIError.from(
								"UNAUTHORIZED",
								METAMASK_ERROR_CODES.ADDRESS_MISMATCH,
							);
						}

						// 4. Consume the nonce to prevent replay attacks
						await ctx.context.internalAdapter.deleteVerificationByIdentifier(
							`metamask:${walletAddress}:${chainId}`,
						);

						// 5. Find or create the user
						let user: User | null = null;
						const existingAccount: MetaMaskAccount | null =
							await ctx.context.adapter.findOne({
								model: "metamaskAccount",
								where: [
									{ field: "address", operator: "eq", value: walletAddress },
									{ field: "chainId", operator: "eq", value: chainId },
								],
							});

						if (existingAccount) {
							user = await ctx.context.adapter.findOne({
								model: "user",
								where: [
									{
										field: "id",
										operator: "eq",
										value: existingAccount.userId,
									},
								],
							});
						}

						if (!user) {
							const emailDomain =
								options?.emailDomainName ??
								getOrigin(ctx.context.baseURL) ??
								"metamask.local";
							const userEmail =
								!isAnon && email
									? email
									: `${walletAddress.toLowerCase()}@${emailDomain}`;

							user = await ctx.context.internalAdapter.createUser({
								name: walletAddress,
								email: userEmail,
								emailVerified: !isAnon && !!email,
								image: "",
							});

							if (!user) {
								throw APIError.from(
									"INTERNAL_SERVER_ERROR",
									METAMASK_ERROR_CODES.FAILED_TO_CREATE_USER,
								);
							}

							await ctx.context.adapter.create({
								model: "metamaskAccount",
								data: {
									userId: user.id,
									address: walletAddress,
									chainId,
									createdAt: new Date(),
								},
							});

							await ctx.context.internalAdapter.createAccount({
								userId: user.id,
								providerId: "metamask",
								accountId: `${walletAddress}:${chainId}`,
								createdAt: new Date(),
								updatedAt: new Date(),
							});
						}

						// 6. Create a new session
						const session =
							await ctx.context.internalAdapter.createSession(user.id);

						if (!session) {
							throw APIError.from(
								"INTERNAL_SERVER_ERROR",
								METAMASK_ERROR_CODES.FAILED_TO_CREATE_SESSION,
							);
						}

						await setSessionCookie(ctx, { session, user });

						return ctx.json({
							token: session.token,
							user: {
								id: user.id,
								walletAddress,
								chainId,
							},
						});
					} catch (error: unknown) {
						if (isAPIError(error)) throw error;
						throw APIError.fromStatus("UNAUTHORIZED", {
							message: "Sign-in failed. Please try again.",
							error:
								error instanceof Error ? error.message : "Unknown error",
							status: 401,
						});
					}
				},
			),
		},
		options,
		$ERROR_CODES: METAMASK_ERROR_CODES,
	}) satisfies BetterAuthPlugin;

export type * from "./types";
