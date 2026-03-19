import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { metamaskClient } from "./client";
import { metamask } from "./index";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** ERC-55 checksum address encoding. */
function toChecksumAddress(address: string): string {
	const addr = address.toLowerCase().replace("0x", "");
	const hash = [...keccak_256(utf8ToBytes(addr))]
		.map((v) => v.toString(16).padStart(2, "0"))
		.join("");
	let ret = "0x";
	for (let i = 0; i < 40; i++) {
		ret +=
			Number.parseInt(hash[i]!, 16) >= 8
				? addr[i]!.toUpperCase()
				: addr[i]!;
	}
	return ret;
}

/** Derive the ERC-55 checksummed Ethereum address from a secp256k1 private key. */
function privateKeyToAddress(privateKey: Uint8Array): string {
	const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
	const pubKeyBytes = publicKey.slice(1); // remove 0x04 prefix
	const addrBytes = keccak_256(pubKeyBytes).slice(12); // last 20 bytes
	return toChecksumAddress(`0x${bytesToHex(addrBytes)}`);
}

/** Sign a message using EIP-191 personal_sign (what MetaMask produces). */
function personalSign(message: string, privateKey: Uint8Array): string {
	const msgBytes = utf8ToBytes(message);
	const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
	const combined = new Uint8Array(prefix.length + msgBytes.length);
	combined.set(prefix);
	combined.set(msgBytes, prefix.length);
	const msgHash = keccak_256(combined);

	const sig = secp256k1.sign(msgHash, privateKey);
	// Encode as r (32) || s (32) || v (1), with v = recoveryBit + 27 (legacy convention)
	const compact = sig.toCompactRawBytes();
	const v = sig.recovery + 27;
	const full = new Uint8Array(65);
	full.set(compact);
	full[64] = v;
	return `0x${bytesToHex(full)}`;
}

// A deterministic private key for tests — never use in production.
const TEST_PRIVATE_KEY = new Uint8Array(32).fill(1); // 0x0101...01
TEST_PRIVATE_KEY[31] = 0x01; // keep it non-zero and well-formed

const TEST_ADDRESS = privateKeyToAddress(TEST_PRIVATE_KEY);
const CHAIN_ID = 1;
const DOMAIN = "example.com";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("metamask plugin", async () => {
	it("nonce endpoint returns a nonce and SIWE message", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data, error } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		expect(error).toBeNull();
		expect(typeof data?.nonce).toBe("string");
		expect(data?.nonce.length).toBeGreaterThan(0);
		expect(data?.message).toContain(DOMAIN);
		expect(data?.message).toContain(TEST_ADDRESS);
		expect(data?.message).toContain(`Nonce: ${data?.nonce}`);
		expect(data?.message).toContain(`Chain ID: ${CHAIN_ID}`);
	});

	it("nonce endpoint rejects invalid wallet address", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { error } = await client.metamask.nonce({
			walletAddress: "not-an-address",
		});

		expect(error).toBeDefined();
		expect(error?.status).toBe(400);
	});

	it("full sign-in flow succeeds with a valid signature", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		// Step 1: get challenge
		const { data: challenge } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		expect(challenge).not.toBeNull();

		// Step 2: sign the SIWE message (simulating MetaMask)
		const signature = personalSign(challenge!.message, TEST_PRIVATE_KEY);

		// Step 3: verify
		const { data, error } = await client.metamask.verify({
			message: challenge!.message,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		expect(error).toBeNull();
		expect(data?.token).toBeDefined();
		// user.walletAddress is present at runtime; cast to access it
		const user = data?.user as unknown as { id: string; walletAddress: string };
		expect(user.walletAddress.toLowerCase()).toBe(TEST_ADDRESS.toLowerCase());
	});

	it("rejects an invalid signature", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data: challenge } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		const { error } = await client.metamask.verify({
			message: challenge!.message,
			signature: `0x${"ab".repeat(32)}${"cd".repeat(32)}1b`, // garbage sig
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		expect(error).toBeDefined();
		expect(error?.status).toBe(401);
	});

	it("rejects when no nonce was requested", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		// Build a message locally without calling the nonce endpoint
		const fakeMessage = `${DOMAIN} wants you to sign in with your Ethereum account:\n${TEST_ADDRESS}\n\nURI: http://localhost\nVersion: 1\nChain ID: 1\nNonce: fakenonce\nIssued At: ${new Date().toISOString()}`;
		const signature = personalSign(fakeMessage, TEST_PRIVATE_KEY);

		const { error } = await client.metamask.verify({
			message: fakeMessage,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		expect(error).toBeDefined();
		expect(error?.status).toBe(401);
		expect(error?.code).toBe("INVALID_OR_EXPIRED_NONCE");
	});

	it("prevents nonce replay attacks", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data: challenge } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		const signature = personalSign(challenge!.message, TEST_PRIVATE_KEY);

		// First verification succeeds
		const first = await client.metamask.verify({
			message: challenge!.message,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		expect(first.error).toBeNull();

		// Second verification with the same nonce fails
		const second = await client.metamask.verify({
			message: challenge!.message,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		expect(second.error).toBeDefined();
		expect(second.error?.status).toBe(401);
		expect(second.error?.code).toBe("INVALID_OR_EXPIRED_NONCE");
	});

	it("same user signs in twice and gets the same account", async () => {
		const { client, auth } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const signIn = async () => {
			const { data: challenge } = await client.metamask.nonce({
				walletAddress: TEST_ADDRESS,
				chainId: CHAIN_ID,
			});
			const sig = personalSign(challenge!.message, TEST_PRIVATE_KEY);
			return client.metamask.verify({
				message: challenge!.message,
				signature: sig,
				walletAddress: TEST_ADDRESS,
				chainId: CHAIN_ID,
			});
		};

		const first = await signIn();
		const second = await signIn();

		expect(first.error).toBeNull();
		expect(second.error).toBeNull();
		expect(second.data?.user.id).toBe(first.data?.user.id);

		// Only one metamaskAccount record should exist
		const accounts: any[] = await (await auth.$context).adapter.findMany({
			model: "metamaskAccount",
			where: [{ field: "address", operator: "eq", value: TEST_ADDRESS }],
		});
		expect(accounts.length).toBe(1);
	});

	it("requires email when anonymous is false", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN, anonymous: false })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data: challenge } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		const signature = personalSign(challenge!.message, TEST_PRIVATE_KEY);

		const { error } = await client.metamask.verify({
			message: challenge!.message,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
			// no email provided
		});

		expect(error).toBeDefined();
		expect(error?.status).toBe(400);
	});

	it("accepts email when anonymous is false", async () => {
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN, anonymous: false })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data: challenge } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});
		const signature = personalSign(challenge!.message, TEST_PRIVATE_KEY);

		const { data, error } = await client.metamask.verify({
			message: challenge!.message,
			signature,
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
			email: "alice@example.com",
		});

		expect(error).toBeNull();
		expect(data?.token).toBeDefined();
	});

	it("includes custom statement in SIWE message", async () => {
		const statement = "I accept the Terms of Service.";
		const { client } = await getTestInstance(
			{ plugins: [metamask({ domain: DOMAIN, statement })] },
			{ clientOptions: { plugins: [metamaskClient()] } },
		);

		const { data } = await client.metamask.nonce({
			walletAddress: TEST_ADDRESS,
			chainId: CHAIN_ID,
		});

		expect(data?.message).toContain(statement);
	});
});
