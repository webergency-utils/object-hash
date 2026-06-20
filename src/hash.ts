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

const MODULE_RANDOM_PREFIX = Math.floor( Math.random() * 0x100000000 ).toString( 36 );
let nextID = 0;
const randomID = () => MODULE_RANDOM_PREFIX + '_' + ( ++nextID );

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

        if( obj instanceof String || obj instanceof Number || obj instanceof Boolean )
        {
            hasher.update( JSON.stringify( obj.valueOf() ));

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
            const aStr = typeof a === 'symbol' ? 'Symbol(' + ( a.description || '' ) + ')' : a;
            const bStr = typeof b === 'symbol' ? 'Symbol(' + ( b.description || '' ) + ')' : b;

            return aStr === bStr ? 0 : aStr > bStr ? 1 : -1;
        });

        hasher.update( '{' );

        let hasWritten = false;

        for( let i = 0; i < sortedKeys.length; ++i )
        {
            const key = sortedKeys[i];
            const val = obj[key];

            if( options.ignoreUndefinedProperties && val === undefined ){ continue }

            if( hasWritten ){ hasher.update( ',' ) }

            const kStr = typeof key === 'symbol' ? 'Symbol(' + ( key.description || '' ) + ')' : JSON.stringify( key );

            hasher.update( kStr + ':' );
            _objectStringify( val, visited, options, hasher );
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
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify } = options;
    const accumulator = new StringAccumulator();

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify } as any, accumulator );

    return accumulator.toString();
}

export default function objectHash( obj: any, options: Partial<ObjectStringifyOptions> = {} ): string
{
    const { sortArrays = false, ignoreUndefinedProperties = true, stringify, bitLength = 64, algorithm = 'fast', encoding = 'base36', hasher } = options;

    const resolvedAlg = resolveAlgorithm( algorithm );
    const mainHasher = createHasher( hasher || ( resolvedAlg === 'murmur3' ? MurmurHash3 : ( resolvedAlg === 'cyrb64' ? Cyrb64Hash : resolvedAlg ) ), bitLength );

    _objectStringify( obj, new Set(), { sortArrays, ignoreUndefinedProperties, stringify } as any, mainHasher );

    return digestToString( mainHasher, encoding );
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
}