import Cyrb64Hash from './alg/cyrb64';
import MurmurHash3 from './alg/murmur3';
import { encodeBytes } from './alg/base';

declare const require: any;

class StringAccumulator
{
    #chunks: string[] = [];

    update( str: string )
    {
        this.#chunks.push( str );
    }

    updateBytes( bytes: Uint8Array )
    {
        this.#chunks.push( bytes.toString() );
    }

    toString(): string
    {
        const s = this.#chunks.join( '' );

        return s;
    }
}

interface Accumulator
{
    update( str: string ): void
    updateBytes( bytes: Uint8Array ): void
}

class HasherAdapter implements Accumulator
{
    #hasher: any;

    constructor( hasher: any )
    {
        this.#hasher = hasher;
    }

    update( str: string )
    {
        this.#hasher.update( str );
    }

    updateBytes( bytes: Uint8Array )
    {
        if( typeof this.#hasher.updateBytes === 'function' )
        {
            this.#hasher.updateBytes( bytes );
        }
        else
        {
            this.#hasher.update( bytes );
        }
    }

    digest(): Uint8Array
    {
        const val = this.#hasher.digest();

        return val;
    }
}

function createHasher( opt: any, bitLength: 64 | 96 | 128 | 192 | 256 ): Accumulator
{
    let instance: any;

    if( typeof opt === 'string' )
    {
        const crypto = require( 'crypto' );

        instance = crypto.createHash( opt );
    }
    else if( typeof opt === 'function' )
    {
        const isClass = /^\s*class\s+/.test( opt.toString() );

        if( isClass )
        {
            instance = new opt( bitLength );
        }
        else
        {
            instance = opt( bitLength );
        }
    }
    else if( typeof opt === 'object' && opt !== null )
    {
        instance = opt;
    }
    else
    {
        instance = new Cyrb64Hash( bitLength );
    }

    return new HasherAdapter( instance );
}

function digestToString( hasher: any, encoding?: 'hex' | 'base36' | 'base62' | 'base64' | 'base64url' ): string
{
    const digest = hasher.digest();

    return typeof digest === 'string' ? digest : encodeBytes( digest, encoding );
}

const HashIndex = new WeakMap<Function | object, string>();

const randomID = (): string =>
{
    if( typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function' )
    {
        const arr = new Uint8Array( 16 );
        crypto.getRandomValues( arr );

        return Array.from( arr, byte => byte.toString( 16 ).padStart( 2, '0' ) ).join( '' );
    }

    try
    {
        const nodeCrypto = require( 'crypto' );

        if( typeof nodeCrypto.randomBytes === 'function' )
        {
            return nodeCrypto.randomBytes( 16 ).toString( 'hex' );
        }
    }
    catch( _ )
    {
        // Fallback
    }

    return Math.random().toString( 36 ).slice( 2 ) + Math.random().toString( 36 ).slice( 2 );
};

function isPlainObject( val: any ): boolean
{
    if( typeof val !== 'object' || val === null ){ return false }

    const proto = Object.getPrototypeOf( val );

    return proto === null || proto === Object.prototype;
}

function getIndexHash( val: Function | object ): string
{
    if( !HashIndex.has( val ))
    {
        const name = val instanceof Function ? ( val.name || 'anonymous' ) : ( val.constructor?.name || 'null' );
        const prefix = ( val instanceof Function ? 'function ' : 'instance ' ) + name;

        HashIndex.set( val, prefix + '_' + randomID());
    }

    return HashIndex.get( val )!;
}

function getEnumerableKeys( obj: any ): (string | symbol)[]
{
    const keys: (string | symbol)[] = Object.keys( obj );
    const symbols = Object.getOwnPropertySymbols( obj );

    for( let i = 0; i < symbols.length; ++i )
    {
        const sym = symbols[i];

        if( Object.prototype.propertyIsEnumerable.call( obj, sym ))
        {
            keys.push( sym );
        }
    }

    return keys;
}

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

export type ObjectStringifyOptions = AlgorithmOptions | HasherOptions;

function _objectStringify( obj: any, visited: Set<any>, options: ObjectStringifyOptions, hasher: Accumulator ): void
{
    if( typeof obj === 'undefined' )
    {
        hasher.update( 'undefined' );

        return;
    }

    if( typeof obj === 'symbol' )
    {
        hasher.update( 'Symbol(' + ( obj.description || '' ) + ')' );

        return;
    }

    if( typeof obj === 'bigint' )
    {
        hasher.update( obj.toString() + 'n' );

        return;
    }

    if( typeof obj === 'number' )
    {
        if( Number.isNaN( obj ))
        {
            hasher.update( 'NaN' );

            return;
        }

        if( !Number.isFinite( obj ))
        {
            hasher.update( obj < 0 ? '-Infinity' : 'Infinity' );

            return;
        }
    }

    if( obj instanceof Function )
    {
        hasher.update( getIndexHash( obj ));

        return;
    }

    if( typeof obj !== 'object' || obj === null )
    {
        hasher.update( JSON.stringify( obj ));

        return;
    }

    if( visited.has( obj ))
    {
        hasher.update( '*Circular*' );

        return;
    }

    visited.add( obj );

    try
    {
        if( obj instanceof Date )
        {
            hasher.update( obj.toISOString());

            return;
        }

        if( obj instanceof RegExp )
        {
            hasher.update( obj.toString());

            return;
        }

        if( obj instanceof Error )
        {
            hasher.update( obj.name + ': ' + obj.message );

            return;
        }

        if( obj instanceof URL )
        {
            hasher.update( 'URL(' + obj.href + ')' );

            return;
        }

        if( typeof URLSearchParams !== 'undefined' && obj instanceof URLSearchParams )
        {
            hasher.update( 'URLSearchParams(' + obj.toString() + ')' );

            return;
        }

        if( obj instanceof String || obj instanceof Number || obj instanceof Boolean )
        {
            hasher.update( JSON.stringify( obj.valueOf() ));

            return;
        }

        if( typeof Symbol !== 'undefined' && obj instanceof Symbol )
        {
            hasher.update( 'Symbol(' + ( obj.valueOf().description || '' ) + ')' );

            return;
        }

        if( obj instanceof ArrayBuffer || ArrayBuffer.isView( obj ))
        {
            const view = obj instanceof ArrayBuffer
                ? new Uint8Array( obj )
                : new Uint8Array( obj.buffer, obj.byteOffset, obj.byteLength );

            const typeName = obj instanceof ArrayBuffer ? 'ArrayBuffer' : obj.constructor.name;

            hasher.update( typeName + '(' );
            hasher.updateBytes( view );
            hasher.update( ')' );

            return;
        }

        if( obj instanceof Set )
        {
            const items = [...obj].map(( v: any ) =>
            {
                const subAccumulator = new StringAccumulator();

                _objectStringify( v, visited, options, subAccumulator );

                return subAccumulator.toString();
            });

            items.sort();
            hasher.update( 'Set(' + items.join( ',' ) + ')' );

            return;
        }

        if( obj instanceof Map )
        {
            const entries = [...obj.entries()].map( ([ key, value ]) =>
            {
                const keyAccumulator = new StringAccumulator();
                _objectStringify( key, visited, options, keyAccumulator );

                const valAccumulator = new StringAccumulator();
                _objectStringify( value, visited, options, valAccumulator );

                return `${ keyAccumulator.toString() }:${ valAccumulator.toString() }`;
            });

            entries.sort();
            hasher.update( 'Map(' + entries.join( ',' ) + ')' );

            return;
        }

        if( obj instanceof Promise )
        {
            hasher.update( 'Promise(pending)' );

            return;
        }

        if( typeof WeakRef !== 'undefined' && obj instanceof WeakRef )
        {
            hasher.update( 'WeakRef(' );
            _objectStringify( obj.deref(), visited, options, hasher );
            hasher.update( ')' );

            return;
        }

        if( typeof WeakMap !== 'undefined' && obj instanceof WeakMap )
        {
            hasher.update( 'WeakMap(opaque)' );

            return;
        }

        if( typeof WeakSet !== 'undefined' && obj instanceof WeakSet )
        {
            hasher.update( 'WeakSet(opaque)' );

            return;
        }

        if( typeof obj.toJSON === 'function' )
        {
            _objectStringify( obj.toJSON(), visited, options, hasher );

            return;
        }

        if( options.stringify )
        {
            const str = options.stringify( obj );

            if( str !== undefined )
            {
                hasher.update( str );

                return;
            }
        }

        if( Array.isArray( obj ))
        {
            if( options.sortArrays )
            {
                const items = obj.map(( v: any ) =>
                {
                    const subAccumulator = new StringAccumulator();

                    _objectStringify( v, visited, options, subAccumulator );

                    return subAccumulator.toString();
                });

                items.sort();
                hasher.update( '[' + items.join( ',' ) + ']' );

                return;
            }

            hasher.update( '[' );

            for( let i = 0; i < obj.length; ++i )
            {
                if( i > 0 ){ hasher.update( ',' ) }
                _objectStringify( obj[i], visited, options, hasher );
            }

            hasher.update( ']' );

            return;
        }

        if( !isPlainObject( obj ))
        {
            hasher.update( getIndexHash( obj ));

            return;
        }

        const keys = getEnumerableKeys( obj );

        const sortedKeys = keys.sort(( a, b ) =>
        {
            if( a === b ){ return 0 }

            const aStr = typeof a === 'symbol' ? 'Symbol(' + ( a.description || '' ) + ')' : a;
            const bStr = typeof b === 'symbol' ? 'Symbol(' + ( b.description || '' ) + ')' : b;

            if( aStr === bStr )
            {
                if( typeof a === 'symbol' && typeof b === 'symbol' )
                {
                    const aValAccumulator = new StringAccumulator();
                    _objectStringify( obj[a], new Set( visited ), options, aValAccumulator );

                    const bValAccumulator = new StringAccumulator();
                    _objectStringify( obj[b], new Set( visited ), options, bValAccumulator );

                    const aValStr = aValAccumulator.toString();
                    const bValStr = bValAccumulator.toString();

                    if( aValStr !== bValStr )
                    {
                        return aValStr > bValStr ? 1 : -1;
                    }
                }

                return 0;
            }

            return aStr > bStr ? 1 : -1;
        });

        hasher.update( '{' );

        let hasWritten = false;

        for( let i = 0; i < sortedKeys.length; ++i )
        {
            const key = sortedKeys[i];

            if( typeof key === 'string' )
            {
                if( options.includeKeys )
                {
                    if( !options.includeKeys.includes( key )){ continue }
                }
                else if( options.excludeKeys && options.excludeKeys.includes( key )){ continue }
            }

            const val = obj[key];

            if( options.ignoreUndefinedProperties && val === undefined ){ continue }

            if( hasWritten ){ hasher.update( ',' ) }

            const kStr = typeof key === 'symbol' ? 'Symbol(' + ( key.description || '' ) + ')' : JSON.stringify( key );

            hasher.update( kStr + ':' );

            if( !options.excludeValues )
            {
                _objectStringify( val, visited, options, hasher );
            }

            hasWritten = true;
        }

        hasher.update( '}' );
    }
    finally
    {
        visited.delete( obj );
    }
}

function resolveAlgorithm( alg?: 'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong' | any ): 'cyrb64' | 'murmur3' | 'sha256'
{
    const a = alg || 'fast';

    if( a === 'fast' || a === 'cyrb64' ){ return 'cyrb64' }
    if( a === 'balanced' || a === 'murmur3' ){ return 'murmur3' }
    if( a === 'strong' || a === 'sha256' ){ return 'sha256' }

    throw new Error( `Unsupported hashing algorithm: ${ a }` );
}

export function objectStringify( obj: any, options: Partial<ObjectStringifyOptions> = {} ): string
{
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, excludeKeys, includeKeys, excludeValues } = options;
    const accumulator = new StringAccumulator();

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, accumulator );

    return accumulator.toString();
}

export default function objectHash( obj: any, options: Partial<ObjectStringifyOptions> = {} ): string
{
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, bitLength = 64, algorithm = 'fast', encoding = 'base36', hasher, excludeKeys, includeKeys, excludeValues } = options;

    const resolvedAlg = resolveAlgorithm( algorithm );
    const mainHasher = createHasher( hasher || ( resolvedAlg === 'murmur3' ? MurmurHash3 : ( resolvedAlg === 'cyrb64' ? Cyrb64Hash : resolvedAlg ) ), bitLength );

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, mainHasher );

    return digestToString( mainHasher, encoding );
}

export function objectHashBytes( obj: any, options: Partial<ObjectStringifyOptions> = {} ): Uint8Array
{
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, bitLength = 64, algorithm = 'fast', hasher, excludeKeys, includeKeys, excludeValues } = options;

    const resolvedAlg = resolveAlgorithm( algorithm );
    const mainHasher = createHasher( hasher || ( resolvedAlg === 'murmur3' ? MurmurHash3 : ( resolvedAlg === 'cyrb64' ? Cyrb64Hash : resolvedAlg ) ), bitLength );

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, mainHasher );

    return (mainHasher as HasherAdapter).digest();
}

export class Hasher
{
    #options: Partial<ObjectStringifyOptions>;

    constructor( options: Partial<ObjectStringifyOptions> = {} )
    {
        this.#options = options;
    }

    stringify( obj: any ): string
    {
        return objectStringify( obj, this.#options );
    }

    hash( obj: any ): string
    {
        return objectHash( obj, this.#options );
    }

    createHash(): StreamingHash
    {
        return new StreamingHash( this.#options );
    }
}

export class StreamingHash
{
    #options: Partial<ObjectStringifyOptions>;
    #accumulator: StringAccumulator;

    constructor( options: Partial<ObjectStringifyOptions> = {} )
    {
        this.#options = options;
        this.#accumulator = new StringAccumulator();
    }

    update( obj: any ): this
    {
        const { sortArrays = false, ignoreUndefinedProperties = true, stringify, excludeKeys, includeKeys, excludeValues } = this.#options;

        _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, this.#accumulator );

        return this;
    }

    digest(): string
    {
        const { bitLength = 64, algorithm = 'fast', encoding = 'base36', hasher } = this.#options;
        const resolvedAlg = resolveAlgorithm( algorithm );
        const mainHasher = createHasher( hasher || ( resolvedAlg === 'murmur3' ? MurmurHash3 : ( resolvedAlg === 'cyrb64' ? Cyrb64Hash : resolvedAlg ) ), bitLength );

        mainHasher.update( this.#accumulator.toString() );

        return digestToString( mainHasher, encoding );
    }

    digestBytes(): Uint8Array
    {
        const { bitLength = 64, algorithm = 'fast', hasher } = this.#options;
        const resolvedAlg = resolveAlgorithm( algorithm );
        const mainHasher = createHasher( hasher || ( resolvedAlg === 'murmur3' ? MurmurHash3 : ( resolvedAlg === 'cyrb64' ? Cyrb64Hash : resolvedAlg ) ), bitLength );

        mainHasher.update( this.#accumulator.toString() );

        return (mainHasher as HasherAdapter).digest();
    }

    reset(): this
    {
        this.#accumulator = new StringAccumulator();

        return this;
    }
}