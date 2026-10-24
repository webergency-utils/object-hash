import Cyrb64Hash from './alg/cyrb64';
import MurmurHash3 from './alg/murmur3';
import Sha256Hash from './alg/sha256';
import 
{ 
    bytesToHex,
    encodeBytes, 
    validateBitLength, 
    validateEncoding, 
    type BitLength, 
    type Encoding 
} 
    from './alg/base';

export { Cyrb64Hash, MurmurHash3, Sha256Hash, type BitLength, type Encoding };

const UTF8_ENCODER = new TextEncoder();

function getNodeCrypto(): any
{
    return ( globalThis as any ).process?.getBuiltinModule?.( 'crypto' );
}

class StringAccumulator implements Accumulator
{
    #chunks : string[] = [];

    update( str: string )
    {
        this.#chunks.push( str );
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
    updateBytes?( bytes: Uint8Array ): void
}

export interface CustomHasher
{
    update( data: any )              : unknown
    updateBytes?( bytes: Uint8Array ): unknown
    digest( encoding?: any )         : Uint8Array | ArrayBuffer | ArrayBufferView | number[] | string
}

export type Algorithm = 'cyrb64' | 'murmur3' | 'sha256' | 'fast' | 'balanced' | 'strong';

export type HasherInput =
    | Algorithm
    | CustomHasher
    | (( bitLength?: BitLength ) => CustomHasher )
    | ( new ( bitLength?: BitLength ) => CustomHasher );

class HasherAdapter implements Accumulator
{
    #hasher      : any;
    #byteLength? : number;

    constructor( hasher: any, byteLength?: number )
    {
        this.#hasher = hasher;
        this.#byteLength = byteLength;
    }

    update( str: string )
    {
        this.#hasher.update( str );
    }

    digest( raw: boolean = false ): Uint8Array | string
    {
        const target = typeof this.#hasher.copy === 'function'
            ? this.#hasher.copy()
            : this.#hasher;
        let val = target.digest();

        if( val instanceof ArrayBuffer || ( typeof SharedArrayBuffer !== 'undefined' && val instanceof SharedArrayBuffer ))
        {
            val = new Uint8Array( val );
        }
        else if( ArrayBuffer.isView( val ) && !( val instanceof Uint8Array ))
        {
            val = new Uint8Array( val.buffer, val.byteOffset, val.byteLength );
        }
        else if( Array.isArray( val ))
        {
            val = Uint8Array.from( val );
        }

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
        let instance: any;

        try
        {
            instance = bitLength !== undefined ? opt( bitLength ) : opt();

            if( instance === undefined )
            {
                instance = bitLength !== undefined ? new opt( bitLength ) : new opt();
            }
        }
        catch( _ )
        {
            instance = bitLength !== undefined ? new opt( bitLength ) : new opt();
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

function createConfiguredHasher( options: Partial<ObjectStringifyOptions> ): { hasher : HasherAdapter, encoding : Encoding }
{
    const { bitLength, algorithm = 'fast', encoding = 'base36', hasher } = options;

    validateEncoding( encoding );

    if( hasher !== undefined )
    {
        return {
            hasher : createHasher( hasher, bitLength ),
            encoding
        };
    }

    return {
        hasher : createHasher( resolveAlgorithm( algorithm ), bitLength ),
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

        return bytesToHex( arr );
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

type BaseOptions = {
    sortArrays                : boolean
    ignoreUndefinedProperties : boolean
    stringify?                : ( obj: any ) => string | undefined
    bitLength?                : BitLength
    encoding?                 : Encoding
    excludeKeys?              : ( string | symbol )[]
    includeKeys?              : ( string | symbol )[]
    excludeValues?            : boolean
};

type AlgorithmOptions = BaseOptions & {
    algorithm? : Algorithm
    hasher?    : never
};

type HasherOptions = BaseOptions & {
    algorithm? : never
    hasher?    : HasherInput
};

export type ObjectStringifyOptions = AlgorithmOptions | HasherOptions;

interface NormalizedStringifyOptions
{
    sortArrays                : boolean
    ignoreUndefinedProperties : boolean
    stringify?                : ( obj: any ) => string | undefined
    excludeKeysSet?           : Set<string | symbol>
    includeKeysSet?           : Set<string | symbol>
    excludeValues?            : boolean
}

function normalizeStringifyOptions( options: Partial<ObjectStringifyOptions> ): NormalizedStringifyOptions
{
    const {
        sortArrays = false,
        ignoreUndefinedProperties = true,
        stringify,
        excludeKeys,
        includeKeys,
        excludeValues
    } = options;

    return {
        sortArrays,
        ignoreUndefinedProperties,
        stringify,
        excludeKeysSet : excludeKeys ? new Set( excludeKeys ) : undefined,
        includeKeysSet : includeKeys ? new Set( includeKeys ) : undefined,
        excludeValues
    };
}

function formatSymbolToken( sym: symbol ): string
{
    const desc = sym.description ?? '';

    return `Symbol(${ desc.length }:${ desc })`;
}

function _objectStringify( obj: any, visited: Set<any>, options: NormalizedStringifyOptions, hasher: Accumulator ): void
{
    if( typeof obj === 'undefined' )
    {
        hasher.update( 'undefined' );

        return;
    }

    if( typeof obj === 'symbol' )
    {
        hasher.update( formatSymbolToken( obj ));

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

    if( options.stringify )
    {
        const str = options.stringify( obj );

        if( str !== undefined )
        {
            hasher.update( str );

            return;
        }
    }

    visited.add( obj );

    try
    {
        if( obj instanceof Date )
        {
            const time = obj.getTime();

            hasher.update( Number.isNaN( time ) ? 'Date(Invalid Date)' : obj.toISOString());

            return;
        }

        if( obj instanceof RegExp )
        {
            hasher.update( `RegExp(${ obj.source.length }:${ obj.source },${ obj.flags })` );

            return;
        }

        if( obj instanceof Error )
        {
            const name = obj.name || 'Error';
            const msg = obj.message || '';
            let out = `Error(${ name.length }:${ name },${ msg.length }:${ msg }`;

            if( 'cause' in obj && ( obj as any ).cause !== undefined )
            {
                const causeAcc = new StringAccumulator();
                _objectStringify(( obj as any ).cause, visited, options, causeAcc );
                out += `,cause=${ causeAcc.toString() }`;
            }

            if( Array.isArray(( obj as any ).errors ))
            {
                const errAcc = new StringAccumulator();
                _objectStringify(( obj as any ).errors, visited, options, errAcc );
                out += `,errors=${ errAcc.toString() }`;
            }

            out += ')';
            hasher.update( out );

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

        if(
            obj instanceof String ||
            obj instanceof Number ||
            obj instanceof Boolean ||
            ( typeof Symbol !== 'undefined' && obj instanceof Symbol ) ||
            ( typeof BigInt !== 'undefined' && obj instanceof BigInt )
        )
        {
            _objectStringify( obj.valueOf(), visited, options, hasher );

            return;
        }

        const isSharedBuf = typeof SharedArrayBuffer !== 'undefined' && obj instanceof SharedArrayBuffer;

        if( obj instanceof ArrayBuffer || isSharedBuf || ArrayBuffer.isView( obj ))
        {
            const view = ArrayBuffer.isView( obj )
                ? new Uint8Array( obj.buffer, obj.byteOffset, obj.byteLength )
                : new Uint8Array( obj as ArrayBuffer );

            const typeName = obj instanceof ArrayBuffer
                ? 'ArrayBuffer'
                : ( isSharedBuf ? 'SharedArrayBuffer' : ( obj.constructor?.name || 'ArrayBufferView' ));

            hasher.update( `${ typeName }(${ view.byteLength }:${ bytesToHex( view ) })` );

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

            const framed = items.map( item => `${ item.length }:${ item }` );

            hasher.update( 'Set{' + framed.join( ',' ) + '}' );

            return;
        }

        if( obj instanceof Map )
        {
            const entries = [...obj.entries()].map(([ key, value ]) =>
            {
                const keyAccumulator = new StringAccumulator();
                _objectStringify( key, visited, options, keyAccumulator );

                const valAccumulator = new StringAccumulator();
                _objectStringify( value, visited, options, valAccumulator );

                const kStr = keyAccumulator.toString();
                const vStr = valAccumulator.toString();

                return `${ kStr.length }:${ kStr }=>${ vStr.length }:${ vStr }`;
            });

            entries.sort();

            const framed = entries.map( entry => `${ entry.length }:${ entry }` );

            hasher.update( 'Map{' + framed.join( ',' ) + '}' );

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
            const replacement = obj.toJSON();

            if( replacement !== obj )
            {
                _objectStringify( replacement, visited, options, hasher );

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

        let strKeys = Object.keys( obj );

        if( options.includeKeysSet )
        {
            strKeys = strKeys.filter( k => options.includeKeysSet!.has( k ));
        }
        else if( options.excludeKeysSet )
        {
            strKeys = strKeys.filter( k => !options.excludeKeysSet!.has( k ));
        }

        strKeys.sort();

        const rawSymbols = Object.getOwnPropertySymbols( obj );
        const symKeys: symbol[] = [];

        for( let i = 0; i < rawSymbols.length; ++i )
        {
            const sym = rawSymbols[i];

            if( !Object.prototype.propertyIsEnumerable.call( obj, sym )){ continue }

            if( options.includeKeysSet )
            {
                if( !options.includeKeysSet.has( sym )){ continue }
            }
            else if( options.excludeKeysSet && options.excludeKeysSet.has( sym )){ continue }

            if( options.ignoreUndefinedProperties && obj[sym] === undefined ){ continue }

            symKeys.push( sym );
        }

        let dupSymValues: Map<symbol, string> | undefined;

        if( symKeys.length > 1 )
        {
            const descCounts = new Map<string, number>();

            for( let i = 0; i < symKeys.length; ++i )
            {
                const desc = symKeys[i].description ?? '';
                descCounts.set( desc, ( descCounts.get( desc ) ?? 0 ) + 1 );
            }

            if( !options.excludeValues && descCounts.size < symKeys.length )
            {
                dupSymValues = new Map<symbol, string>();
                const sameRefValues = new Map<any, string>();

                for( let i = 0; i < symKeys.length; ++i )
                {
                    const sym = symKeys[i];
                    const desc = sym.description ?? '';

                    if(( descCounts.get( desc ) ?? 0 ) > 1 )
                    {
                        const symVal = obj[sym];

                        if( sameRefValues.has( symVal ))
                        {
                            dupSymValues.set( sym, sameRefValues.get( symVal )! );
                        }
                        else
                        {
                            const valAcc = new StringAccumulator();
                            _objectStringify( symVal, visited, options, valAcc );
                            const serializedVal = valAcc.toString();
                            sameRefValues.set( symVal, serializedVal );
                            dupSymValues.set( sym, serializedVal );
                        }
                    }
                }
            }

            symKeys.sort(( a, b ) =>
            {
                const aDesc = a.description ?? '';
                const bDesc = b.description ?? '';

                if( aDesc !== bDesc )
                {
                    return aDesc > bDesc ? 1 : -1;
                }

                if( dupSymValues )
                {
                    const aVal = dupSymValues.get( a )!;
                    const bVal = dupSymValues.get( b )!;

                    if( aVal !== bVal )
                    {
                        return aVal > bVal ? 1 : -1;
                    }
                }

                return 0;
            });
        }

        hasher.update( '{' );

        let hasWritten = false;

        for( let i = 0; i < strKeys.length; ++i )
        {
            const key = strKeys[i];
            const val = obj[key];

            if( options.ignoreUndefinedProperties && val === undefined ){ continue }

            if( hasWritten ){ hasher.update( ',' ) }

            hasher.update( JSON.stringify( key ) + ':' );

            if( !options.excludeValues )
            {
                _objectStringify( val, visited, options, hasher );
            }

            hasWritten = true;
        }

        for( let i = 0; i < symKeys.length; ++i )
        {
            const sym = symKeys[i];
            const val = obj[sym];

            if( options.ignoreUndefinedProperties && val === undefined ){ continue }

            if( hasWritten ){ hasher.update( ',' ) }

            hasher.update( formatSymbolToken( sym ) + ':' );

            if( !options.excludeValues )
            {
                if( dupSymValues && dupSymValues.has( sym ))
                {
                    hasher.update( dupSymValues.get( sym )! );
                }
                else
                {
                    _objectStringify( val, visited, options, hasher );
                }
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

export function objectStringify( obj: any, options: Partial<ObjectStringifyOptions> = {}): string
{
    const accumulator = new StringAccumulator();

    _objectStringify( obj, new Set(), normalizeStringifyOptions( options ), accumulator );

    return accumulator.toString();
}

export default function objectHash( obj: any, options: Partial<ObjectStringifyOptions> = {}): string
{
    const { hasher: mainHasher, encoding } = createConfiguredHasher( options );

    _objectStringify( obj, new Set(), normalizeStringifyOptions( options ), mainHasher );

    return digestToString( mainHasher, encoding );
}

export function objectHashBytes( obj: any, options: Partial<ObjectStringifyOptions> = {}): Uint8Array
{
    const { hasher: mainHasher } = createConfiguredHasher( options );

    _objectStringify( obj, new Set(), normalizeStringifyOptions( options ), mainHasher );

    return mainHasher.digest( true ) as Uint8Array;
}

export class Hasher
{
    #options : Partial<ObjectStringifyOptions>;

    constructor( options: Partial<ObjectStringifyOptions> = {})
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
    #options          : Partial<ObjectStringifyOptions>;
    #stringifyOptions : NormalizedStringifyOptions;
    #hasher!          : HasherAdapter;
    #encoding!        : Encoding;

    constructor( options: Partial<ObjectStringifyOptions> = {})
    {
        this.#options = options;
        this.#stringifyOptions = normalizeStringifyOptions( options );

        this.reset();
    }

    update( obj: any ): this
    {
        const chunkAccumulator = new StringAccumulator();

        _objectStringify( obj, new Set(), this.#stringifyOptions, chunkAccumulator );

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