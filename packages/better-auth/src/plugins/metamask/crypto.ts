import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { toChecksumAddress } from "../../utils/hashing";

function hexToBytes(hex: string): Uint8Array {
	const h = hex.startsWith("0x") ? hex.slice(2) : hex;
	if (h.length % 2 !== 0) throw new Error("Invalid hex string");
	const bytes = new Uint8Array(h.length / 2);
	for (let i = 0; i < h.length; i += 2) {
		bytes[i / 2] = Number.parseInt(h.slice(i, i + 2), 16);
	}
	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Recovers the Ethereum address from an EIP-191 personal_sign signature.
 * MetaMask uses personal_sign which prefixes the message with
 * "\x19Ethereum Signed Message:\n" + message.length before hashing.
 *
 * @returns The ERC-55 checksummed address of the signer
 */
export function recoverPersonalSignAddress(
	message: string,
	signature: string,
): string {
	const msgBytes = utf8ToBytes(message);
	const prefix = utf8ToBytes(
		`\x19Ethereum Signed Message:\n${msgBytes.length}`,
	);
	const combined = new Uint8Array(prefix.length + msgBytes.length);
	combined.set(prefix);
	combined.set(msgBytes, prefix.length);
	const msgHash = keccak_256(combined);

	const sigBytes = hexToBytes(signature);
	if (sigBytes.length !== 65) {
		throw new Error(`Invalid signature length: expected 65, got ${sigBytes.length}`);
	}

	let recoveryBit = sigBytes[64]!;
	// MetaMask adds 27 to the recovery bit (legacy Ethereum convention)
	if (recoveryBit >= 27) recoveryBit -= 27;
	if (recoveryBit !== 0 && recoveryBit !== 1) {
		throw new Error(`Invalid recovery bit: ${recoveryBit}`);
	}

	const rAndSHex = bytesToHex(sigBytes.slice(0, 64));
	const sig = secp256k1.Signature.fromCompact(rAndSHex).addRecoveryBit(
		recoveryBit,
	);
	const publicKey = sig.recoverPublicKey(msgHash);

	// Uncompressed public key without the 0x04 prefix = 64 bytes (x || y)
	const pubKeyBytes = publicKey.toRawBytes(false).slice(1);
	// Ethereum address = last 20 bytes of keccak256(pubKey)
	const addrBytes = keccak_256(pubKeyBytes).slice(12);
	return toChecksumAddress(`0x${bytesToHex(addrBytes)}`);
}

/**
 * Builds an EIP-4361 (Sign-In with Ethereum) formatted message.
 *
 * MetaMask will render this message to the user when signing.
 */
export function createSIWEMessage({
	domain,
	address,
	statement,
	uri,
	chainId,
	nonce,
	issuedAt,
	resources,
}: {
	domain: string;
	address: string;
	statement?: string;
	uri: string;
	chainId: number;
	nonce: string;
	issuedAt: string;
	resources?: string[];
}): string {
	const lines: string[] = [
		`${domain} wants you to sign in with your Ethereum account:`,
		address,
		"",
	];

	if (statement) {
		lines.push(statement, "");
	}

	lines.push(
		`URI: ${uri}`,
		"Version: 1",
		`Chain ID: ${chainId}`,
		`Nonce: ${nonce}`,
		`Issued At: ${issuedAt}`,
	);

	if (resources && resources.length > 0) {
		lines.push("Resources:", ...resources.map((r) => `- ${r}`));
	}

	return lines.join("\n");
}
