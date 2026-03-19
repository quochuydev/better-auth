import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const METAMASK_ERROR_CODES = defineErrorCodes({
	INVALID_OR_EXPIRED_NONCE: "Invalid or expired nonce",
	INVALID_SIGNATURE: "Invalid signature",
	ADDRESS_MISMATCH: "Signature does not match wallet address",
	FAILED_TO_CREATE_USER: "Failed to create user",
	FAILED_TO_CREATE_SESSION: "Failed to create session",
});
