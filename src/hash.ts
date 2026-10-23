import Cyrb64Hash from './alg/cyrb64';
import MurmurHash3 from './alg/murmur3';
import Sha256Hash from './alg/sha256';
import 
{ 
    encodeBytes, 
    validateBitLength, 
    validateEncoding, 
    type BitLength, 
    type Encoding 
} 
from './alg/base';

export { Cyrb64Hash, MurmurHash3, Sha256Hash };

const UTF8_ENCODER = new TextEncoder();

function getNodeCrypto(): any
{
    try
    {
        return ( globalThis as any ).process?.getBuiltinModule?.( 'crypto' );
    }
    catch( _ )
    {
        return undefined;
    }
}

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

export interface Accumulator
{
    update( str: string ): void
    updateBytes( bytes: Uint8Array ): void
}

export interface CustomHasher
{
    update( data: any )             : unknown
    updateBytes?( bytes: Uint8Array ): unknown
    digest( encoding?: any )        : string | Uint8Array
}

export type Algorithm = 'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong';

export type HasherInput =
    | Algorithm
    | CustomHasher
    | (( bitLength?: BitLength ) => CustomHasher )
    | ( new ( bitLength?: BitLength ) => CustomHasher );

class HasherAdapter implements Accumulator
{
    #hasher: any;
    #byteLength?: number;

    constructor( hasher: any, byteLength?: number )
    {
        this.#hasher = hasher;
        this.#byteLength = byteLength;
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

    digest( raw: boolean = false ): Uint8Array | string
    {
        const target = typeof this.#hasher.copy === 'function'
            ? this.#hasher.copy()
            : this.#hasher;
        const val = target.digest();

        if( val instanceof Uint8Array )
        {
            const len = this.#byteLength !== undefined
                ? Math.min( val.byteLength, this.#byteLength )
                : val.byteLength;

            if( val.constructor !== Uint8Array || len !== val.byteLength )
            {
                return new Uint8Array( val.buffer, val.byteOffset, len );
            }

            return val;
        }

        if( raw )
        {
            const encoded = UTF8_ENCODER.encode( String( val ));

            return this.#byteLength !== undefined
                ? encoded.subarray( 0, this.#byteLength )
                : encoded;
        }

        return String( val );
    }
}

function defaultBitLengthForAlgorithm( alg: 'cyrb64' | 'murmur3' | 'sha256' ): BitLength
{
    if( alg === 'cyrb64' ){ return 64 }

    if( alg === 'murmur3' ){ return 128 }

    return 256;
}

function createSha256Hasher( bitLength: BitLength ): HasherAdapter
{
    const nodeCrypto = getNodeCrypto();

    if( nodeCrypto && typeof nodeCrypto.createHash === 'function' )
    {
        return new HasherAdapter( nodeCrypto.createHash( 'sha256' ), bitLength / 8 );
    }

    return new HasherAdapter( new Sha256Hash( bitLength ));
}

function createHasher( opt: any, bitLength?: BitLength ): HasherAdapter
{
    if( bitLength !== undefined )
    {
        validateBitLength( bitLength );
    }

    if( typeof opt === 'string' )
    {
        if( opt === 'cyrb64' || opt === 'fast' )
        {
            const b = bitLength ?? 64;

            return new HasherAdapter( new Cyrb64Hash( b ));
        }

        if( opt === 'murmur3' || opt === 'balanced' )
        {
            const b = bitLength ?? 128;

            return new HasherAdapter( new MurmurHash3( b ));
        }

        if( opt === 'sha256' || opt === 'strong' )
        {
            const b = bitLength ?? 256;

            return createSha256Hasher( b );
        }

        const nodeCrypto = getNodeCrypto();

        if( nodeCrypto && typeof nodeCrypto.createHash === 'function' )
        {
            return new HasherAdapter( nodeCrypto.createHash( opt ), bitLength ? bitLength / 8 : undefined );
        }

        throw new Error( `Unsupported hashing algorithm: ${ opt }` );
    }

    if( typeof opt === 'function' )
    {
        const b = bitLength ?? 64;
        let instance: any;

        try
        {
            instance = opt( b );

            if( instance === undefined )
            {
                instance = new opt( b );
            }
        }
        catch( _ )
        {
            instance = new opt( b );
        }

        return new HasherAdapter( instance, bitLength ? bitLength / 8 : undefined );
    }

    if( typeof opt === 'object' && opt !== null )
    {
        return new HasherAdapter( opt, bitLength ? bitLength / 8 : undefined );
    }

    const b = bitLength ?? 64;

    return new HasherAdapter( new Cyrb64Hash( b ));
}

function createConfiguredHasher( options: Partial<ObjectStringifyOptions> ): { hasher: HasherAdapter, encoding: Encoding }
{
    const { bitLength, algorithm = 'fast', encoding = 'base36', hasher } = options;

    validateEncoding( encoding );

    if( bitLength !== undefined )
    {
        validateBitLength( bitLength );
    }

    if( hasher !== undefined )
    {
        return {
            hasher: createHasher( hasher, bitLength ),
            encoding
        };
    }

    const resolvedAlg = resolveAlgorithm( algorithm );
    const resolvedBits = bitLength ?? defaultBitLengthForAlgorithm( resolvedAlg );

    return {
        hasher: createHasher( resolvedAlg, resolvedBits ),
        encoding
    };
}

function digestToString( hasher: HasherAdapter, encoding: Encoding = 'base36' ): string
{
    const digest = hasher.digest( false );

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

    const nodeCrypto = getNodeCrypto();

    if( nodeCrypto && typeof nodeCrypto.randomBytes === 'function' )
    {
        return nodeCrypto.randomBytes( 16 ).toString( 'hex' );
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
    stringify?                  : ( obj: any ) => string | undefined
    bitLength?                  : BitLength
    encoding?                   : Encoding
    excludeKeys?                : ( string | symbol )[]
    includeKeys?                : ( string | symbol )[]
    excludeValues?              : boolean
}

type AlgorithmOptions = BaseOptions & {
    algorithm?                  : Algorithm
    hasher?                     : never
}

type HasherOptions = BaseOptions & {
    algorithm?                  : never
    hasher?                     : HasherInput
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
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, excludeKeys, includeKeys, excludeValues } = options;
    const { hasher: mainHasher, encoding } = createConfiguredHasher( options );

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, mainHasher );

    return digestToString( mainHasher, encoding );
}

export function objectHashBytes( obj: any, options: Partial<ObjectStringifyOptions> = {} ): Uint8Array
{
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, excludeKeys, includeKeys, excludeValues } = options;
    const { hasher: mainHasher } = createConfiguredHasher( options );

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, mainHasher );

    return mainHasher.digest( true ) as Uint8Array;
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
    #hasher: HasherAdapter;
    #encoding: Encoding;

    constructor( options: Partial<ObjectStringifyOptions> = {} )
    {
        this.#options = options;

        const configured = createConfiguredHasher( this.#options );
        this.#hasher = configured.hasher;
        this.#encoding = configured.encoding;
    }

    update( obj: any ): this
    {
        const { sortArrays = false, ignoreUndefinedProperties = true, stringify, excludeKeys, includeKeys, excludeValues } = this.#options;
        const chunkAccumulator = new StringAccumulator();

        _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify, excludeKeys, includeKeys, excludeValues } as any, chunkAccumulator );

        const chunk = chunkAccumulator.toString();

        this.#hasher.update( `${ chunk.length }:` );
        this.#hasher.update( chunk );

        return this;
    }

    digest(): string
    {
        return digestToString( this.#hasher, this.#encoding );
    }

    digestBytes(): Uint8Array
    {
        return this.#hasher.digest( true ) as Uint8Array;
    }

    reset(): this
    {
        const configured = createConfiguredHasher( this.#options );
        this.#hasher = configured.hasher;
        this.#encoding = configured.encoding;

        return this;
    }
}