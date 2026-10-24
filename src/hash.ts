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

const EMPTY_OPTIONS: Partial<ObjectStringifyOptions> = {};

const DEFAULT_STRINGIFY_OPTIONS: NormalizedStringifyOptions = {
    sortArrays                : false,
    ignoreUndefinedProperties : true,
    stringify                 : undefined,
    excludeKeysSet            : undefined,
    includeKeysSet            : undefined,
    excludeValues             : undefined
};

const SHARED_VISITED = new Set<any>();

function acquireVisited(): Set<any>
{
    return SHARED_VISITED.size === 0 ? SHARED_VISITED : new Set();
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

    if(
        !sortArrays &&
        ignoreUndefinedProperties &&
        !stringify &&
        !excludeKeys &&
        !includeKeys &&
        !excludeValues
    )
    {
        return DEFAULT_STRINGIFY_OPTIONS;
    }

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

function serializeString( str: string ): string
{
    const len = str.length;

    if( len < 48 )
    {
        for( let i = 0; i < len; ++i )
        {
            const c = str.charCodeAt( i );

            if( c < 32 || c >= 0xd800 || c === 34 || c === 92 )
            {
                return JSON.stringify( str );
            }
        }

        return '"' + str + '"';
    }

    return JSON.stringify( str );
}

function sortStringKeys( keys: string[]): void
{
    const len = keys.length;

    if( len <= 1 ){ return }

    if( len === 2 )
    {
        if( keys[0] > keys[1])
        {
            const tmp = keys[0];
            keys[0] = keys[1];
            keys[1] = tmp;
        }

        return;
    }

    if( len === 3 )
    {
        if( keys[0] > keys[1])
        {
            const tmp = keys[0];
            keys[0] = keys[1];
            keys[1] = tmp;
        }

        if( keys[1] > keys[2])
        {
            const tmp = keys[1];
            keys[1] = keys[2];
            keys[2] = tmp;

            if( keys[0] > keys[1])
            {
                const tmp2 = keys[0];
                keys[0] = keys[1];
                keys[1] = tmp2;
            }
        }

        return;
    }

    keys.sort();
}

function _objectStringify( obj: any, visited: Set<any>, options: NormalizedStringifyOptions ): string
{
    if( obj === null )
    {
        return 'null';
    }

    const type = typeof obj;

    if( type === 'string' )
    {
        return serializeString( obj );
    }

    if( type === 'number' )
    {
        if( Number.isFinite( obj ))
        {
            return '' + obj;
        }

        return Number.isNaN( obj ) ? 'NaN' : ( obj < 0 ? '-Infinity' : 'Infinity' );
    }

    if( type === 'boolean' )
    {
        return obj ? 'true' : 'false';
    }

    if( type === 'undefined' )
    {
        return 'undefined';
    }

    if( type === 'symbol' )
    {
        return formatSymbolToken( obj );
    }

    if( type === 'bigint' )
    {
        return obj.toString() + 'n';
    }

    if( type === 'function' )
    {
        return getIndexHash( obj );
    }

    if( visited.has( obj ))
    {
        return '*Circular*';
    }

    if( options.stringify )
    {
        const str = options.stringify( obj );

        if( str !== undefined )
        {
            return str;
        }
    }

    visited.add( obj );

    try
    {
        const isArr = Array.isArray( obj );
        const isPlain = !isArr && isPlainObject( obj );

        if( !isArr && !isPlain )
        {
            if( obj instanceof Date )
            {
                const time = obj.getTime();

                return Number.isNaN( time ) ? 'Date(Invalid Date)' : obj.toISOString();
            }

            if( obj instanceof RegExp )
            {
                return `RegExp(${ obj.source.length }:${ obj.source },${ obj.flags })`;
            }

            if( obj instanceof Error )
            {
                const name = obj.name || 'Error';
                const msg = obj.message || '';
                let out = `Error(${ name.length }:${ name },${ msg.length }:${ msg }`;

                if( 'cause' in obj && ( obj as any ).cause !== undefined )
                {
                    out += `,cause=${ _objectStringify(( obj as any ).cause, visited, options ) }`;
                }

                if( Array.isArray(( obj as any ).errors ))
                {
                    out += `,errors=${ _objectStringify(( obj as any ).errors, visited, options ) }`;
                }

                return out + ')';
            }

            if( obj instanceof URL )
            {
                return 'URL(' + obj.href + ')';
            }

            if( typeof URLSearchParams !== 'undefined' && obj instanceof URLSearchParams )
            {
                return 'URLSearchParams(' + obj.toString() + ')';
            }

            if(
                obj instanceof String ||
                obj instanceof Number ||
                obj instanceof Boolean ||
                ( typeof Symbol !== 'undefined' && obj instanceof Symbol ) ||
                ( typeof BigInt !== 'undefined' && obj instanceof BigInt )
            )
            {
                return _objectStringify( obj.valueOf(), visited, options );
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

                return `${ typeName }(${ view.byteLength }:${ bytesToHex( view ) })`;
            }

            if( obj instanceof Set )
            {
                const items: string[] = [];

                for( const v of obj )
                {
                    items.push( _objectStringify( v, visited, options ));
                }

                items.sort();

                for( let i = 0; i < items.length; ++i )
                {
                    const item = items[i];
                    items[i] = `${ item.length }:${ item }`;
                }

                return 'Set{' + items.join( ',' ) + '}';
            }

            if( obj instanceof Map )
            {
                const entries: string[] = [];

                for( const [ key, value ] of obj.entries())
                {
                    const kStr = _objectStringify( key, visited, options );
                    const vStr = _objectStringify( value, visited, options );

                    entries.push( `${ kStr.length }:${ kStr }=>${ vStr.length }:${ vStr }` );
                }

                entries.sort();

                for( let i = 0; i < entries.length; ++i )
                {
                    const entry = entries[i];
                    entries[i] = `${ entry.length }:${ entry }`;
                }

                return 'Map{' + entries.join( ',' ) + '}';
            }

            if( obj instanceof Promise )
            {
                return 'Promise(pending)';
            }

            if( typeof WeakRef !== 'undefined' && obj instanceof WeakRef )
            {
                return 'WeakRef(' + _objectStringify( obj.deref(), visited, options ) + ')';
            }

            if( typeof WeakMap !== 'undefined' && obj instanceof WeakMap )
            {
                return 'WeakMap(opaque)';
            }

            if( typeof WeakSet !== 'undefined' && obj instanceof WeakSet )
            {
                return 'WeakSet(opaque)';
            }
        }

        if( typeof obj.toJSON === 'function' )
        {
            const replacement = obj.toJSON();

            if( replacement !== obj )
            {
                return _objectStringify( replacement, visited, options );
            }
        }

        if( isArr )
        {
            if( options.sortArrays )
            {
                const items = obj.map(( v: any ) => _objectStringify( v, visited, options ));

                items.sort();

                return '[' + items.join( ',' ) + ']';
            }

            let out = '[';

            for( let i = 0; i < obj.length; ++i )
            {
                if( i > 0 ){ out += ',' }
                out += _objectStringify( obj[i], visited, options );
            }

            return out + ']';
        }

        if( !isPlain )
        {
            return getIndexHash( obj );
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

        sortStringKeys( strKeys );

        let out = '{';
        let hasWritten = false;

        for( let i = 0; i < strKeys.length; ++i )
        {
            const key = strKeys[i];
            const val = obj[key];

            if( options.ignoreUndefinedProperties && val === undefined ){ continue }

            out += ( hasWritten ? ',' : '' ) + serializeString( key ) + ':';

            if( !options.excludeValues )
            {
                out += _objectStringify( val, visited, options );
            }

            hasWritten = true;
        }

        const rawSymbols = Object.getOwnPropertySymbols( obj );

        if( rawSymbols.length > 0 )
        {
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
                                const serializedVal = _objectStringify( symVal, visited, options );
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

            for( let i = 0; i < symKeys.length; ++i )
            {
                const sym = symKeys[i];
                const val = obj[sym];

                if( options.ignoreUndefinedProperties && val === undefined ){ continue }

                out += ( hasWritten ? ',' : '' ) + formatSymbolToken( sym ) + ':';

                if( !options.excludeValues )
                {
                    if( dupSymValues && dupSymValues.has( sym ))
                    {
                        out += dupSymValues.get( sym )!;
                    }
                    else
                    {
                        out += _objectStringify( val, visited, options );
                    }
                }

                hasWritten = true;
            }
        }

        return out + '}';
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

export function objectStringify( obj: any, options: Partial<ObjectStringifyOptions> = EMPTY_OPTIONS ): string
{
    return _objectStringify( obj, acquireVisited(), normalizeStringifyOptions( options ));
}

export default function objectHash( obj: any, options: Partial<ObjectStringifyOptions> = EMPTY_OPTIONS ): string
{
    const { hasher: mainHasher, encoding } = createConfiguredHasher( options );

    mainHasher.update( _objectStringify( obj, acquireVisited(), normalizeStringifyOptions( options )));

    return digestToString( mainHasher, encoding );
}

export function objectHashBytes( obj: any, options: Partial<ObjectStringifyOptions> = EMPTY_OPTIONS ): Uint8Array
{
    const { hasher: mainHasher } = createConfiguredHasher( options );

    mainHasher.update( _objectStringify( obj, acquireVisited(), normalizeStringifyOptions( options )));

    return mainHasher.digest( true ) as Uint8Array;
}

export class Hasher
{
    #options          : Partial<ObjectStringifyOptions>;
    #stringifyOptions : NormalizedStringifyOptions;

    constructor( options: Partial<ObjectStringifyOptions> = EMPTY_OPTIONS )
    {
        this.#options = options;
        this.#stringifyOptions = normalizeStringifyOptions( options );
    }

    stringify( obj: any ): string
    {
        return _objectStringify( obj, acquireVisited(), this.#stringifyOptions );
    }

    hash( obj: any ): string
    {
        const { hasher: mainHasher, encoding } = createConfiguredHasher( this.#options );

        mainHasher.update( _objectStringify( obj, acquireVisited(), this.#stringifyOptions ));

        return digestToString( mainHasher, encoding );
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

    constructor( options: Partial<ObjectStringifyOptions> = EMPTY_OPTIONS )
    {
        this.#options = options;
        this.#stringifyOptions = normalizeStringifyOptions( options );

        this.reset();
    }

    update( obj: any ): this
    {
        const chunk = _objectStringify( obj, acquireVisited(), this.#stringifyOptions );

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