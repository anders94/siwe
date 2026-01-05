import { recoverPublicKey, hashes, Signature, etc, Point } from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

// Register HMAC-SHA256 and SHA256 for secp256k1 v3
hashes.hmacSha256 = (k, m) => hmac(sha256, k, m);
hashes.sha256 = (...m) => sha256(etc.concatBytes(...m));

const ETH_MESSAGE_PREFIX = '\x19Ethereum Signed Message:\n';

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export function hexToBytes(hex: string): Uint8Array {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function utf8ToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

export function hashMessage(message: string): Uint8Array {
    const messageBytes = utf8ToBytes(message);
    const prefix = utf8ToBytes(`${ETH_MESSAGE_PREFIX}${messageBytes.length}`);
    const combined = new Uint8Array(prefix.length + messageBytes.length);
    combined.set(prefix);
    combined.set(messageBytes, prefix.length);
    return keccak_256(combined);
}

export function recoverAddress(message: string, signature: string): string {
    const msgHash = hashMessage(message);
    let sigHex = signature;
    if (sigHex.startsWith('0x')) sigHex = sigHex.slice(2);

    if (sigHex.length !== 130) {
        throw new Error('Invalid signature length. Expected 65 bytes (r + s + v).');
    }

    const r = sigHex.slice(0, 64);
    const s = sigHex.slice(64, 128);
    let v = parseInt(sigHex.slice(128, 130), 16);
    if (v >= 27) v -= 27;

    // Construct 65-byte signature for v3 recoverPublicKey (recovery + r + s)
    // noble-secp256k1 expects recovery byte first for 'recovered' format.
    const signatureBytes = new Uint8Array(65);
    signatureBytes[0] = v;
    signatureBytes.set(hexToBytes(r + s), 1);

    // v3 recoverPublicKey(signature, hash)
    // console.log('SigBytes Len:', signatureBytes.length);
    const pubKey = recoverPublicKey(signatureBytes, msgHash);

    // pubKey is Uint8Array, convert to uncompressed hex
    const point = Point.fromHex(bytesToHex(pubKey));
    const pubKeyHex = point.toHex(false);

    const pubKeyBytes = hexToBytes(pubKeyHex);
    // Address is last 20 bytes of keccak256(pubKey[1..])
    const addressBytes = keccak_256(pubKeyBytes.slice(1)).slice(-20);

    const addr = '0x' + bytesToHex(addressBytes);
    return addr;
}

export async function checkSignature(message: string, signature: string, expectedAddress: string): Promise<boolean> {
    try {
        const recovered = recoverAddress(message, signature);
        return recovered.toLowerCase() === expectedAddress.toLowerCase();
    } catch (e) {
        return false;
    }
}
