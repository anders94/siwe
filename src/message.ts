import { checkSignature } from './utils.js';

export interface SiweMessageOptions {
    domain: string;
    address: string;
    statement?: string;
    uri: string;
    version: string;
    chainId: number;
    nonce: string;
    issuedAt: string;
    expirationTime?: string;
    notBefore?: string;
    requestId?: string;
    resources?: string[];
}

export class SiweMessage {
    domain: string;
    address: string;
    statement?: string;
    uri: string;
    version: string;
    chainId: number;
    nonce: string;
    issuedAt: string;
    expirationTime?: string;
    notBefore?: string;
    requestId?: string;
    resources?: string[];

    constructor(param: SiweMessageOptions) {
        this.domain = param.domain;
        this.address = param.address;
        this.statement = param.statement;
        this.uri = param.uri;
        this.version = param.version;
        this.chainId = param.chainId;
        this.nonce = param.nonce;
        this.issuedAt = param.issuedAt;
        this.expirationTime = param.expirationTime;
        this.notBefore = param.notBefore;
        this.requestId = param.requestId;
        this.resources = param.resources;
    }

    prepareMessage(): string {
        let message = `${this.domain} wants you to sign in with your Ethereum account:\n${this.address}\n\n`;

        if (this.statement) {
            message += `${this.statement}\n\n`;
        }

        message += `URI: ${this.uri}\n`;
        message += `Version: ${this.version}\n`;
        message += `Chain ID: ${this.chainId}\n`;
        message += `Nonce: ${this.nonce}\n`;
        message += `Issued At: ${this.issuedAt}`;

        if (this.expirationTime) {
            message += `\nExpiration Time: ${this.expirationTime}`;
        }

        if (this.notBefore) {
            message += `\nNot Before: ${this.notBefore}`;
        }

        if (this.requestId) {
            message += `\nRequest ID: ${this.requestId}`;
        }

        if (this.resources && this.resources.length > 0) {
            message += `\nResources:`;
            for (const res of this.resources) {
                message += `\n- ${res}`;
            }
        }

        return message;
    }

    toMessage(): string {
        return this.prepareMessage();
    }

    async validate(signature: string): Promise<SiweMessage> {
        const message = this.prepareMessage();
        const isValid = await checkSignature(message, signature, this.address);
        if (!isValid) throw new Error('Signature does not match address of the message.');

        const now = new Date();
        if (this.expirationTime) {
            const exp = new Date(this.expirationTime);
            if (now >= exp) throw new Error('Message expired.');
        }

        if (this.notBefore) {
            const nbf = new Date(this.notBefore);
            if (now < nbf) throw new Error('Message not yet valid.');
        }

        return this;
    }

    static fromString(str: string): SiweMessage {
        const REGEX =
            /^([^:]+) wants you to sign in with your Ethereum account:\n(0x[a-fA-F0-9]{40})\n\n(?:((?:.|\n)+)\n\n)?URI: ([^\n]+)\nVersion: ([^\n]+)\nChain ID: ([^\n]+)\nNonce: ([^\n]+)\nIssued At: ([^\n]+)(?:\nExpiration Time: ([^\n]+))?(?:\nNot Before: ([^\n]+))?(?:\nRequest ID: ([^\n]+))?(?:\nResources:((?:\n- [^\n]+)*))?$/;

        const match = str.match(REGEX);
        if (!match) {
            throw new Error('Message could not be parsed.');
        }

        const [
            _,
            domain,
            address,
            statement,
            uri,
            version,
            chainId,
            nonce,
            issuedAt,
            expirationTime,
            notBefore,
            requestId,
            resourcesRaw,
        ] = match;

        const resources = resourcesRaw
            ? resourcesRaw.split('\n- ').filter((r) => r !== '')
            : undefined;

        return new SiweMessage({
            domain,
            address,
            statement,
            uri,
            version,
            chainId: parseInt(chainId),
            nonce,
            issuedAt,
            expirationTime,
            notBefore,
            requestId,
            resources,
        });
    }
}
