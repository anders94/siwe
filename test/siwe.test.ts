import { describe, it, expect } from 'vitest';
import { SiweMessage } from '../src/message.js';
import * as secp from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { hashMessage, recoverAddress } from '../src/utils.js';

// Config
secp.hashes.hmacSha256 = (k, m) => hmac(sha256, k, m);
secp.hashes.sha256 = (...m) => sha256(secp.etc.concatBytes(...m));

const DOMAIN = 'myapp.com';
const URI = 'https://myapp.com';

// Helper to create a wallet and sign
function createWallet() {
    const privateKey = secp.utils.randomSecretKey();
    const pubKey = secp.getPublicKey(privateKey, false);
    const address = '0x' + Array.from(keccak_256(pubKey.slice(1)).slice(-20))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return {
        privateKey,
        address,
        sign: async (msg: string) => {
            const hash = hashMessage(msg); // Just for logging/debugging if needed
            // v3 sign returns Uint8Array (r, s)
            const sigBytes = secp.sign(hash, privateKey);

            const compact = secp.etc.bytesToHex(sigBytes);

            // Find recovery bit
            const sigHex = '0x' + compact;
            // Try v=27
            let v = 27;
            let recovered = '';
            try {
                // We need to manually construct the signature with v=27 for recoverAddress
                // recoverAddress expects 65 bytes hex (130 chars) if we pass strings?
                // Actually recoverAddress handles 130 chars.
                // utils.recoverAddress expects (message, signature)
                // signature must be 130 chars hex -> 65 bytes.
                recovered = recoverAddress(msg, sigHex + v.toString(16));
            } catch (e) { }

            if (recovered.toLowerCase() !== address.toLowerCase()) {
                v = 28;
            }

            return '0x' + compact + v.toString(16);
        }
    };
}

describe('SiweMessage', () => {
    it('should create and serialize a message correctly', () => {
        const msg = new SiweMessage({
            domain: DOMAIN,
            address: '0x1234567890123456789012345678901234567890',
            statement: 'Sign in to App',
            uri: URI,
            version: '1',
            chainId: 1,
            nonce: 'randomNonce',
            issuedAt: '2022-01-01T00:00:00.000Z'
        });

        const str = msg.prepareMessage();
        expect(str).toContain(`${DOMAIN} wants you to sign in with your Ethereum account:`);
        expect(str).toContain('0x1234567890123456789012345678901234567890');
        expect(str).toContain('Sign in to App');
        expect(str).toContain(`URI: ${URI}`);
        expect(str).toContain('Nonce: randomNonce');
    });

    it('should parse a valid message string', () => {
        const str = `${DOMAIN} wants you to sign in with your Ethereum account:
0x1234567890123456789012345678901234567890

Sign in to App

URI: ${URI}
Version: 1
Chain ID: 1
Nonce: randomNonce
Issued At: 2022-01-01T00:00:00.000Z
Request ID: some-id
Resources:
- resource1
- resource2`;

        const msg = SiweMessage.fromString(str);
        expect(msg.domain).toBe(DOMAIN);
        expect(msg.address).toBe('0x1234567890123456789012345678901234567890');
        expect(msg.statement).toBe('Sign in to App');
        expect(msg.uri).toBe(URI);
        expect(msg.resources).toEqual(['resource1', 'resource2']);
    });

    it('should validate a correct signature', async () => {
        const wallet = createWallet();
        const msg = new SiweMessage({
            domain: DOMAIN,
            address: wallet.address,
            uri: URI,
            version: '1',
            chainId: 1,
            nonce: 'nonce123',
            issuedAt: new Date().toISOString()
        });

        const signature = await wallet.sign(msg.prepareMessage());
        const result = await msg.validate(signature);
        expect(result).toBe(msg);
    });

    it('should fail validation for incorrect signature', async () => {
        const wallet = createWallet();
        const otherWallet = createWallet();

        const msg = new SiweMessage({
            domain: DOMAIN,
            address: wallet.address,
            uri: URI,
            version: '1',
            chainId: 1,
            nonce: 'nonce123',
            issuedAt: new Date().toISOString()
        });

        const signature = await otherWallet.sign(msg.prepareMessage()); // valid signature, wrong address

        await expect(msg.validate(signature)).rejects.toThrow();
    });

    it('should fail if expired', async () => {
        const wallet = createWallet();
        const msg = new SiweMessage({
            domain: DOMAIN,
            address: wallet.address,
            uri: URI,
            version: '1',
            chainId: 1,
            nonce: 'nonce123',
            issuedAt: new Date().toISOString(),
            expirationTime: new Date(Date.now() - 10000).toISOString() // expired
        });

        const signature = await wallet.sign(msg.prepareMessage());
        await expect(msg.validate(signature)).rejects.toThrow('Message expired');
    });

    it('should fail if not yet valid', async () => {
        const wallet = createWallet();
        const msg = new SiweMessage({
            domain: DOMAIN,
            address: wallet.address,
            uri: URI,
            version: '1',
            chainId: 1,
            nonce: 'nonce123',
            issuedAt: new Date().toISOString(),
            notBefore: new Date(Date.now() + 10000).toISOString() // future
        });

        const signature = await wallet.sign(msg.prepareMessage());
        await expect(msg.validate(signature)).rejects.toThrow('Message not yet valid');
    });
});
