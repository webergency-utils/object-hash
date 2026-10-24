# @webergency-utils/object-hash

A fast, deterministic object hashing and stringification library supporting cyrb64, MurmurHash3, and SHA-256 algorithms. It provides full support for modern JavaScript types, stable symbol sorting, and custom serialization options.

[![npm version](https://img.shields.io/npm/v/@webergency-utils/object-hash.svg)](https://www.npmjs.com/package/@webergency-utils/object-hash)
[![License](https://img.shields.io/npm/l/@webergency-utils/object-hash.svg)](https://github.com/webergency-utils/object-hash)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](#maintenance)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://www.npmjs.com/package/@webergency-utils/object-hash?activeTab=dependencies)
[![npm downloads](https://img.shields.io/npm/dm/@webergency-utils/object-hash.svg)](https://www.npmjs.com/package/@webergency-utils/object-hash)
<br>
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/webergency-utils/object-hash/badge)](https://securityscorecards.dev/viewer/?uri=github.com/webergency-utils/object-hash)
[![codecov](https://codecov.io/gh/webergency-utils/object-hash/graph/badge.svg)](https://codecov.io/gh/webergency-utils/object-hash)
[![Tests](https://github.com/webergency-utils/object-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/webergency-utils/object-hash/actions/workflows/ci.yml)
[![CodeQL](https://github.com/webergency-utils/object-hash/actions/workflows/codeql.yml/badge.svg)](https://github.com/webergency-utils/object-hash/actions/workflows/codeql.yml)





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
// '{"meta":{"active":true,"id":Symbol(6:unique)},"name":"Alice","tags":Set{7:"admin",6:"user"}}'
```

## Installation & Setup

Install the package via npm:

```bash
npm install @webergency-utils/object-hash
```

No external runtime configuration, peer dependencies, or build setup steps are required.

## Architecture & Internals

The library uses a depth-first traversal strategy to serialize arbitrary JavaScript values into a stable, normalized string format before hashing.

* **Key Sorting**: Object keys are sorted deterministically, partitioning string keys before symbol keys. In the case of duplicate Symbol descriptions, keys are sorted by the memoized serialized string representation of their mapped values to guarantee process-run stability in linear depth time.
* **Canonical Framing & Binary Encoding**: Variable-length tokens (`Symbol`, `RegExp`, `Error`, `Set`, `Map`, and `StreamingHash` chunks) use length-prefixed framing (`<len>:<payload>`) to prevent delimiter-injection collisions. Binary buffers and views (`ArrayBuffer`, `SharedArrayBuffer`, `DataView`, `TypedArray`, `Buffer`) are serialized uniformly as `<TypeTag>(<byteLength>:<lowercaseHex>)`.
* **Isomorphic SHA-256**: `sha256` / `strong` automatically uses Node's built-in `crypto` module when available (`process.getBuiltinModule('crypto')`) and falls back to the bundled zero-dependency pure-JS `Sha256Hash` implementation in browsers, Workers, and edge runtimes.
* **Reference Hashing**: Functions and custom class instances are hashed by identity. When first encountered, they are assigned a stateless, high-entropy process-lifetime unique ID using cryptographic APIs (Web Crypto `crypto.getRandomValues` or Node.js `crypto.randomBytes` depending on environment availability), falling back to `Math.random()` in legacy runtimes.
* **Collection Handling**: `Map` and `Set` collections are sorted by their serialized string representations before hashing to ensure stability regardless of insertion order.
* **Memory Management**: Tree traversal uses a temporary `Set` of visited references to detect circular loops safely without causing stack overflows. The visited set is cleaned up in a `finally` block to prevent memory leaks and ensure shared object references are traversed correctly.

## Glossary

* **`objectHash`**: The default function to generate a hash string from any value.
* **`objectStringify`**: A helper function returning a deterministic string serialization of any value.
* **`objectHashBytes`**: A helper function returning the raw `Uint8Array` digest bytes of any value.
* **`Hasher`**: A stateless helper class pre-configured with options for multiple hash and stringify runs.
* **`StreamingHash`**: A class that supports stateful streaming / incremental updates and resets.
* **`Cyrb64Hash` / `MurmurHash3` / `Sha256Hash`**: Direct incremental hash algorithm classes for 64-256 bit digests.
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
export type BitLength = 64 | 96 | 128 | 192 | 256;
export type Encoding = 'hex' | 'base36' | 'base62' | 'base64' | 'base64url';
export type Algorithm = 'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong';

export type CustomHasher = {
    update( data: string ): void
    updateBytes?( bytes: Uint8Array ): void
    digest(): Uint8Array | ArrayBuffer | ArrayBufferView | number[] | string
};

export type HasherInput =
    | Algorithm
    | CustomHasher
    | ( () => CustomHasher )
    | ( new () => CustomHasher );

type BaseOptions = {
    sortArrays                  : boolean
    ignoreUndefinedProperties   : boolean
    stringify?                  : ( obj: object ) => string | undefined
    bitLength?                  : BitLength
    encoding?                   : Encoding
    excludeKeys?                : Array<string | symbol>
    includeKeys?                : Array<string | symbol>
    excludeValues?              : boolean
};

type AlgorithmOptions = BaseOptions & {
    algorithm?                  : Algorithm
    hasher?                     : undefined
};

type HasherOptions = BaseOptions & {
    algorithm?                  : undefined
    hasher?                     : HasherInput
};
```

#### Property Descriptions

* **`sortArrays`**: `boolean` (Default: `false`) - When `true`, arrays are sorted by their serialized element representations before hashing.
* **`ignoreUndefinedProperties`**: `boolean` (Default: `true`) - When `true`, object keys with `undefined` values are skipped.
* **`stringify`**: `( obj: object ) => string | undefined` (Optional) - A custom serialization hook evaluated on non-null objects **before** built-in `instanceof` handlers (`Date`, `RegExp`, `Set`, `Map`, binary views, etc.) and **before** `obj.toJSON()`. If it returns `undefined`, standard built-in/default serialization runs as a fallback.
* **`bitLength`**: `64 | 96 | 128 | 192 | 256` (Default: `64` for `cyrb64`/`fast`, `128` for `murmur3`/`balanced`, `256` for `sha256`/`strong`) - The hash digest length in bits. Explicit `bitLength` overrides are honored uniformly across all algorithms (including `sha256`/`strong` and custom hashers) by slicing the digest bytes to `bitLength / 8`. Passing an unsupported `bitLength` throws an `Error`.
* **`encoding`**: `'hex' | 'base36' | 'base62' | 'base64' | 'base64url'` (Default: `'base36'`) - The string encoding of the hash digest output. Passing an unsupported `encoding` throws an `Error`.
* **`excludeKeys`**: `Array<string | symbol>` (Optional) - List of string or symbol keys to exclude recursively from plain objects during serialization.
* **`includeKeys`**: `Array<string | symbol>` (Optional) - Allowlist of string or symbol keys to include recursively. Takes precedence over `excludeKeys` if both are specified.
* **`excludeValues`**: `boolean` (Optional) - When `true`, hashes only the shape/schema of objects, ignoring property values.
* **`algorithm`**: `'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong'` (Default: `'fast'`) - The hashing algorithm to use.
  * `'fast'` and `'cyrb64'` map to `Cyrb64Hash` (default `bitLength`: `64`).
  * `'balanced'` and `'murmur3'` map to `MurmurHash3` (default `bitLength`: `128`).
  * `'strong'` and `'sha256'` map to `Sha256Hash` / Node `crypto` SHA-256 (default `bitLength`: `256`).
* **`hasher`**: `HasherInput` - An algorithm alias string, a `CustomHasher` instance, a factory function `() => CustomHasher`, or a custom hasher class constructor `new () => CustomHasher`.

## Maintenance

This package is actively maintained.

Bug reports and pull requests are welcome. Security issues and critical
regressions are prioritized. New features are considered when they align
with the package's existing scope.
