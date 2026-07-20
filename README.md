# @webergency-utils/object-hash

[![npm version](https://img.shields.io/npm/v/@webergency-utils/object-hash.svg)](https://www.npmjs.com/package/@webergency-utils/object-hash)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/webergency-utils/object-hash/badge)](https://securityscorecards.dev/viewer/?uri=github.com/webergency-utils/object-hash)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](#maintenance)
[![npm downloads](https://img.shields.io/npm/dm/@webergency-utils/object-hash.svg)](https://www.npmjs.com/package/@webergency-utils/object-hash)
[![License](https://img.shields.io/npm/l/@webergency-utils/object-hash.svg)](https://github.com/webergency-utils/object-hash)

A fast, deterministic object hashing and stringification library supporting cyrb64, MurmurHash3, and SHA-256 algorithms. It provides full support for modern JavaScript types, stable symbol sorting, and custom serialization options.

## TL;DR

```typescript
import objectHash, { objectStringify } from '@webergency-utils/object-hash';

const data = {
    name: 'Alice',
    tags: new Set([ 'admin', 'user' ]),
    meta: { active: true, id: Symbol( 'unique' ) }
};

// Generate a deterministic hash string (default: cyrb64, base36)
const hash = objectHash( data );
console.log( hash ); // e.g., "1h8sk5h0yvwomq"

// Serialize to a stable, deterministic string representation
const stableString = objectStringify( data );
console.log( stableString );
// '{"meta":{"active":true,"id":Symbol(unique)},"name":"Alice","tags":Set("admin","user")}'
```

## Installation & Setup

Install the package via npm:

```bash
npm install @webergency-utils/object-hash
```

No external runtime configuration, peer dependencies, or build setup steps are required.

## Architecture & Internals

The library uses a depth-first traversal strategy to serialize arbitrary JavaScript values into a stable, normalized string format before hashing.

* **Key Sorting**: Object keys are sorted deterministically. In the case of duplicate Symbol descriptions, keys are sorted by the serialized string representation of their mapped values to guarantee process-run stability.
* **Reference Hashing**: Functions and custom class instances are hashed by identity. When first encountered, they are assigned a stateless, high-entropy process-lifetime unique ID using cryptographic APIs (Web Crypto `crypto.getRandomValues` or Node.js `crypto.randomBytes` depending on environment availability), falling back to `Math.random()` in legacy runtimes.
* **Collection Handling**: `Map` and `Set` collections are sorted by their serialized string representations before hashing to ensure stability regardless of insertion order.
* **Memory Management**: Tree traversal uses a temporary `Set` of visited references to detect circular loops safely without causing stack overflows. The visited set is cleaned up in a `finally` block to prevent memory leaks and ensure shared object references are traversed correctly.

## Glossary

* **`objectHash`**: The default function to generate a hash string from any value.
* **`objectStringify`**: A helper function returning a deterministic string serialization of any value.
* **`objectHashBytes`**: A helper function returning the raw `Uint8Array` digest bytes of any value.
* **`Hasher`**: A stateless helper class pre-configured with options for multiple hash and stringify runs.
* **`StreamingHash`**: A class that supports stateful streaming / incremental updates and resets.
* **`ObjectStringifyOptions`**: The options type configuration for algorithms, serialization limits, and key filters.

## API Reference

### `objectHash`

Generates a deterministic hash string from any JavaScript value.

```typescript
export default function objectHash( obj: any, options?: Partial<ObjectStringifyOptions> ): string;
```

#### Parameters

* **`obj`**: `any` - The input value to hash.
* **`options`**: `Partial<ObjectStringifyOptions>` (Optional) - Configuration options for serialization and hashing.

#### Returns

`string` - The encoded hash digest (default encoding is `base36`).

#### Code Example

```typescript
import objectHash from '@webergency-utils/object-hash';

const hash = objectHash( { x: 1, y: 2 }, { algorithm: 'sha256', encoding: 'hex' } );
```

---

### `objectStringify`

Generates a stable, deterministic string representation of any JavaScript value.

```typescript
export function objectStringify( obj: any, options?: Partial<ObjectStringifyOptions> ): string;
```

#### Parameters

* **`obj`**: `any` - The input value to serialize.
* **`options`**: `Partial<ObjectStringifyOptions>` (Optional) - Configuration options.

#### Returns

`string` - The stable serialized string.

#### Code Example

```typescript
import { objectStringify } from '@webergency-utils/object-hash';

const str = objectStringify( { b: 2, a: 1 } ); // '{"a":1,"b":2}'
```

---

### `objectHashBytes`

Generates a deterministic raw byte digest of any JavaScript value.

```typescript
export function objectHashBytes( obj: any, options?: Partial<ObjectStringifyOptions> ): Uint8Array;
```

#### Parameters

* **`obj`**: `any` - The input value to hash.
* **`options`**: `Partial<ObjectStringifyOptions>` (Optional) - Configuration options.

#### Returns

`Uint8Array` - The raw hash digest bytes.

#### Code Example

```typescript
import { objectHashBytes } from '@webergency-utils/object-hash';

const bytes = objectHashBytes( { x: 1 } );
```

---

### `Hasher`

A stateless helper class pre-configured with options for multiple hash and stringify runs.

```typescript
export class Hasher
{
    constructor( options?: Partial<ObjectStringifyOptions> );
    stringify( obj: any ): string;
    hash( obj: any ): string;
    createHash(): StreamingHash;
}
```

#### Constructor Parameters

* **`options`**: `Partial<ObjectStringifyOptions>` (Optional) - Configuration options.

#### Methods

* **`stringify( obj: any ): string`**: Generates a stable string serialization of `obj` using the configured options.
* **`hash( obj: any ): string`**: Hashes `obj` and returns the encoded hash digest.
* **`createHash(): StreamingHash`**: Creates a new stateful `StreamingHash` instance configured with the same options.

---

### `StreamingHash`

A class for stateful, incremental/streaming updates and hashing.

```typescript
export class StreamingHash
{
    constructor( options?: Partial<ObjectStringifyOptions> );
    update( obj: any ): this;
    digest(): string;
    digestBytes(): Uint8Array;
    reset(): this;
}
```

#### Code Example

```typescript
import { StreamingHash, Hasher } from '@webergency-utils/object-hash';

// Using direct class construction
const stream = new StreamingHash( { algorithm: 'murmur3' } );
stream.update( 'chunk 1' ).update( { key: 'value' } );
const hash1 = stream.digest();

// Reusing options from a stateless Hasher instance
const hasher = new Hasher( { algorithm: 'sha256' } );
const stream2 = hasher.createHash();
stream2.update( 'another chunk' );
const hash2 = stream2.digest();
```

---

### `ObjectStringifyOptions`

```typescript
type ObjectStringifyOptions = AlgorithmOptions | HasherOptions;
```

#### Type Declaration

`ObjectStringifyOptions` is a union of two types depending on whether you provide an algorithm name or a custom hasher instance.

```typescript
type BaseOptions = {
    sortArrays                  : boolean
    ignoreUndefinedProperties   : boolean
    stringify?                  : ( obj: object ) => string | undefined
    bitLength?                  : 64 | 96 | 128 | 192 | 256
    encoding?                   : 'hex' | 'base36' | 'base62' | 'base64' | 'base64url'
    excludeKeys?                : string[]
    includeKeys?                : string[]
    excludeValues?              : boolean
}

type AlgorithmOptions = BaseOptions & {
    algorithm?                  : 'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong'
    hasher                      : never
}

type HasherOptions = BaseOptions & {
    algorithm                   : never
    hasher                      : Accumulator
}

interface Accumulator {
    update( str: string ): void;
    updateBytes( bytes: Uint8Array ): void;
}
```

#### Property Descriptions

* **`sortArrays`**: `boolean` (Default: `false`) - When `true`, arrays are sorted by their serialized element representations before hashing.
* **`ignoreUndefinedProperties`**: `boolean` (Default: `true`) - When `true`, object keys with `undefined` values are skipped.
* **`stringify`**: `( obj: object ) => string | undefined` (Optional) - A custom serialization function. If it returns `undefined`, the standard serialization logic is used as a fallback.
* **`bitLength`**: `64 | 96 | 128 | 192 | 256` (Default: `64` for cyrb64, `128` for murmur3) - The hash length in bits.
* **`encoding`**: `'hex' | 'base36' | 'base62' | 'base64' | 'base64url'` (Default: `'base36'`) - The string encoding of the hash digest output.
* **`excludeKeys`**: `string[]` (Optional) - List of property keys to exclude recursively from plain objects during serialization.
* **`includeKeys`**: `string[]` (Optional) - Allowlist of property keys to include recursively. Takes precedence over `excludeKeys` if both are specified.
* **`excludeValues`**: `boolean` (Optional) - When `true`, hashes only the shape/schema of objects, ignoring property values.
* **`algorithm`**: `'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong'` (Default: `'fast'`) - The hashing algorithm to use.
  * `'fast'` and `'cyrb64'` map to cyrb64 (64-bit).
  * `'balanced'` and `'murmur3'` map to MurmurHash3 (128-bit).
  * `'strong'` and `'sha256'` map to SHA-256 (256-bit).
* **`hasher`**: `Accumulator` - A custom hasher instance conforming to the `Accumulator` interface (e.g., custom wrappers or native Node `crypto` hashes).

## Maintenance

This package is actively maintained.

Bug reports and pull requests are welcome. Security issues and critical
regressions are prioritized. New features are considered when they align
with the package's existing scope.
