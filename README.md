# @anders94/siwe

A lightweight TypeScript implementation of [Sign-In with Ethereum (EIP-4361)](https://eips.ethereum.org/EIPS/eip-4361).

## Why this library?

Most SIWE implementations depend on heavy Ethereum libraries like ethers.js or viem. This library uses only [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) and [@noble/hashes](https://github.com/paulmillr/noble-hashes) for cryptographic operations, resulting in a much smaller bundle size for applications that don't need a full Ethereum library.

## Installation

```bash
npm install @anders94/siwe
```

## Usage

### Creating a SIWE message

```typescript
import { SiweMessage } from '@anders94/siwe';

const message = new SiweMessage({
  domain: 'myapp.com',
  address: '0x1234567890123456789012345678901234567890',
  statement: 'Sign in to My App',
  uri: 'https://myapp.com',
  version: '1',
  chainId: 1,
  nonce: 'randomNonce123',
  issuedAt: new Date().toISOString(),
  expirationTime: new Date(Date.now() + 3600000).toISOString(), // optional
  notBefore: new Date().toISOString(), // optional
  requestId: 'request-123', // optional
  resources: ['https://myapp.com/api'] // optional
});

// Get the message string to be signed
const messageString = message.prepareMessage();
```

### Parsing a SIWE message

```typescript
import { SiweMessage } from '@anders94/siwe';

const messageString = `myapp.com wants you to sign in with your Ethereum account:
0x1234567890123456789012345678901234567890

Sign in to My App

URI: https://myapp.com
Version: 1
Chain ID: 1
Nonce: randomNonce123
Issued At: 2024-01-01T00:00:00.000Z`;

const message = SiweMessage.fromString(messageString);
```

### Validating a signature

```typescript
import { SiweMessage } from '@anders94/siwe';

const message = new SiweMessage({
  domain: 'myapp.com',
  address: userAddress,
  uri: 'https://myapp.com',
  version: '1',
  chainId: 1,
  nonce: 'randomNonce123',
  issuedAt: new Date().toISOString()
});

try {
  // Validates signature and checks expiration/notBefore times
  await message.validate(signature);
  console.log('Signature valid!');
} catch (error) {
  console.error('Validation failed:', error.message);
}
```

### Low-level signature verification

```typescript
import { checkSignature } from '@anders94/siwe';

const isValid = await checkSignature(message, signature, expectedAddress);
```

## API

### `SiweMessage`

#### Constructor Options

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `domain` | `string` | Yes | The domain requesting the sign-in |
| `address` | `string` | Yes | Ethereum address (0x-prefixed) |
| `uri` | `string` | Yes | URI of the resource |
| `version` | `string` | Yes | SIWE version (typically "1") |
| `chainId` | `number` | Yes | EIP-155 chain ID |
| `nonce` | `string` | Yes | Randomized token for replay protection |
| `issuedAt` | `string` | Yes | ISO 8601 timestamp |
| `statement` | `string` | No | Human-readable message |
| `expirationTime` | `string` | No | ISO 8601 expiration time |
| `notBefore` | `string` | No | ISO 8601 time before which message is invalid |
| `requestId` | `string` | No | Request identifier |
| `resources` | `string[]` | No | List of resource URIs |

#### Methods

- `prepareMessage(): string` - Returns the EIP-4361 formatted message string
- `toMessage(): string` - Alias for `prepareMessage()`
- `validate(signature: string): Promise<SiweMessage>` - Validates signature and time constraints
- `static fromString(str: string): SiweMessage` - Parses an EIP-4361 message string

### `checkSignature`

```typescript
function checkSignature(
  message: string,
  signature: string,
  expectedAddress: string
): Promise<boolean>
```

Low-level function to verify an Ethereum signature matches an expected address.

## License

MIT
