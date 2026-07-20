import 
{ 
    describe, 
    test, 
    expect 
} 
from 'vitest';
import objectHash, { objectStringify, Hasher, objectHashBytes, StreamingHash } from '../hash';
import 
{ 
    bytesToHex,
    bytesToBase36, 
    bytesToBase62,
    bytesToBase64,
    bytesToBase64Url,
    encodeBytes
} 
from '../alg/base';
import Cyrb64Hash from '../alg/cyrb64';
import MurmurHash3 from '../alg/murmur3';


describe( 'object-hash tests', () =>
{
    test( 'should hash primitive values and match expected types', () =>
    {
        expect( objectHash( null )).toBe( objectHash( null ));
        expect( objectHash( undefined )).toBe( objectHash( undefined ));
        expect( objectHash( 123 )).toBe( objectHash( 123 ));
        expect( objectHash( 'string' )).toBe( objectHash( 'string' ));
        expect( objectHash( true )).toBe( objectHash( true ));
    });

    test( 'should distinguish NaN, Infinity, -Infinity, and null', () =>
    {
        expect( objectHash( NaN )).not.toBe( objectHash( null ));
        expect( objectHash( Infinity )).not.toBe( objectHash( null ));
        expect( objectHash( -Infinity )).not.toBe( objectHash( null ));
        expect( objectHash( NaN )).not.toBe( objectHash( Infinity ));
        expect( objectHash( Infinity )).not.toBe( objectHash( -Infinity ));

        expect( objectStringify( NaN )).toBe( 'NaN' );
        expect( objectStringify( Infinity )).toBe( 'Infinity' );
        expect( objectStringify( -Infinity )).toBe( '-Infinity' );
    });

    test( 'should hash simple objects deterministically regardless of key order', () =>
    {
        const obj1 = { a: 1, b: 2 };
        const obj2 = { b: 2, a: 1 };

        expect( objectHash( obj1 )).toBe( objectHash( obj2 ));
    });

    test( 'should respect ignoreUndefinedProperties option', () =>
    {
        const obj1 = { a: 1, b: undefined };
        const obj2 = { a: 1 };

        expect( objectHash( obj1 )).toBe( objectHash( obj2 ));

        const obj3 = { a: 1, b: undefined };
        const hashWithUndefinedIncluded = objectHash( obj3, { ignoreUndefinedProperties: false });
        const hashWithUndefinedExcluded = objectHash( obj3, { ignoreUndefinedProperties: true });

        expect( hashWithUndefinedIncluded ).not.toBe( hashWithUndefinedExcluded );
    });

    test( 'should handle Object.create(null) without throwing and hash deterministically', () =>
    {
        const nullObj1 = Object.create( null );
        nullObj1.a = 1;
        nullObj1.b = 2;

        const nullObj2 = Object.create( null );
        nullObj2.b = 2;
        nullObj2.a = 1;

        expect( () => objectHash( nullObj1 )).not.toThrow();
        expect( objectHash( nullObj1 )).toBe( objectHash( nullObj2 ));
    });

    test( 'should handle Circular reference objects safely and deterministically', () =>
    {
        const circ1: any = { name: 'circular' };
        circ1.self = circ1;

        const circ2: any = { name: 'circular' };
        circ2.self = circ2;

        expect( () => objectHash( circ1 )).not.toThrow();
        expect( objectHash( circ1 )).toBe( objectHash( circ2 ));
        expect( objectStringify( circ1 )).toBe( '{"name":"circular","self":*Circular*}' );
    });

    test( 'should not treat shared object references as circular references', () =>
    {
        const shared = { x: 1 };
        const obj = { a: shared, b: shared };

        expect( objectStringify( obj )).not.toContain( '*Circular*' );
        expect( objectStringify( obj )).toBe( '{"a":{"x":1},"b":{"x":1}}' );
    });

    test( 'should handle circular Set and Map references without stack overflow', () =>
    {
        const set: any = new Set();
        set.add( set );

        expect( () => objectHash( set )).not.toThrow();
        expect( objectStringify( set )).toBe( 'Set(*Circular*)' );

        const map: any = new Map();
        map.set( map, map );

        expect( () => objectHash( map )).not.toThrow();
        expect( objectStringify( map )).toBe( 'Map(*Circular*:*Circular*)' );
    });

    test( 'should handle Date and RegExp object types', () =>
    {
        const date1 = new Date( '2026-06-20T00:00:00.000Z' );
        const date2 = new Date( '2026-06-20T00:00:00.000Z' );
        const date3 = new Date( '2026-06-21T00:00:00.000Z' );

        expect( objectHash( date1 )).toBe( objectHash( date2 ));
        expect( objectHash( date1 )).not.toBe( objectHash( date3 ));

        const regex1 = /abc/g;
        const regex2 = /abc/g;
        const regex3 = /abc/i;

        expect( objectHash( regex1 )).toBe( objectHash( regex2 ));
        expect( objectHash( regex1 )).not.toBe( objectHash( regex3 ));
    });

    test( 'should handle BigInt, Error, URL, and boxed primitives', () =>
    {
        // BigInt tests
        const b1 = 12345678901234567890n;
        const b2 = 12345678901234567890n;
        const b3 = 98765432109876543210n;

        expect( objectHash( b1 )).toBe( objectHash( b2 ));
        expect( objectHash( b1 )).not.toBe( objectHash( b3 ));
        expect( objectStringify( b1 )).toBe( '12345678901234567890n' );

        // Error tests
        const err1 = new Error( 'something went wrong' );
        const err2 = new Error( 'something went wrong' );
        const err3 = new TypeError( 'something went wrong' );

        expect( objectHash( err1 )).toBe( objectHash( err2 ));
        expect( objectHash( err1 )).not.toBe( objectHash( err3 ));
        expect( objectStringify( err1 )).toBe( 'Error: something went wrong' );
        expect( objectStringify( err3 )).toBe( 'TypeError: something went wrong' );

        // URL tests
        const url1 = new URL( 'https://example.com/path?query=1' );
        const url2 = new URL( 'https://example.com/path?query=1' );
        const url3 = new URL( 'https://example.com/other' );

        expect( objectHash( url1 )).toBe( objectHash( url2 ));
        expect( objectHash( url1 )).not.toBe( objectHash( url3 ));
        expect( objectStringify( url1 )).toBe( 'URL(https://example.com/path?query=1)' );

        // Boxed primitive tests
        const strBox1 = new String( 'hello' );
        const strBox2 = new String( 'hello' );
        const strBox3 = new String( 'world' );

        expect( objectHash( strBox1 )).toBe( objectHash( strBox2 ));
        expect( objectHash( strBox1 )).not.toBe( objectHash( strBox3 ));
        expect( objectStringify( strBox1 )).toBe( '"hello"' );

        const numBox = new Number( 42 );
        expect( objectStringify( numBox )).toBe( '42' );

        const boolBox = new Boolean( true );
        expect( objectStringify( boolBox )).toBe( 'true' );
    });

    test( 'should hash Sets deterministically regardless of insertion order', () =>
    {
        const set1 = new Set();
        set1.add( { id: 2 } );
        set1.add( { id: 1 } );

        const set2 = new Set();
        set2.add( { id: 1 } );
        set2.add( { id: 2 } );

        expect( objectHash( set1 )).toBe( objectHash( set2 ));
    });

    test( 'should hash Maps deterministically regardless of insertion order', () =>
    {
        const map1 = new Map();
        map1.set( { id: 2 }, 'two' );
        map1.set( { id: 1 }, 'one' );

        const map2 = new Map();
        map2.set( { id: 1 }, 'one' );
        map2.set( { id: 2 }, 'two' );

        expect( objectHash( map1 )).toBe( objectHash( map2 ));
    });

    test( 'should hash and stringify Maps with different key types deterministically', () =>
    {
        const map1 = new Map<any, any>();
        map1.set( 'stringKey', 'value1' );
        map1.set( 123, 'value2' );
        map1.set( { a: 1 }, 'value3' );
        map1.set( [ 1, 2 ], 'value4' );
        map1.set( new Date( '2026-06-20T00:00:00.000Z' ), 'value5' );

        const map2 = new Map<any, any>();
        map2.set( new Date( '2026-06-20T00:00:00.000Z' ), 'value5' );
        map2.set( [ 1, 2 ], 'value4' );
        map2.set( { a: 1 }, 'value3' );
        map2.set( 123, 'value2' );
        map2.set( 'stringKey', 'value1' );

        expect( objectHash( map1 )).toBe( objectHash( map2 ));

        const expectedStringify = 'Map("stringKey":"value1",123:"value2",2026-06-20T00:00:00.000Z:"value5",[1,2]:"value4",{"a":1}:"value3")';
        expect( objectStringify( map1 )).toBe( expectedStringify );
    });

    test( 'should sort Arrays when sortArrays: true is configured', () =>
    {
        const arr1 = [ { id: 2 }, { id: 1 } ];
        const arr2 = [ { id: 1 }, { id: 2 } ];

        expect( objectHash( arr1, { sortArrays: true } )).toBe( objectHash( arr2, { sortArrays: true } ));
        expect( objectHash( arr1, { sortArrays: false } )).not.toBe( objectHash( arr2, { sortArrays: false } ));
    });

    test( 'should treat custom class instances as unique references', () =>
    {
        class CustomClass
        {
            name: string;
            constructor( name: string )
            {
                this.name = name;
            }
        }

        const inst1 = new CustomClass( 'test' );
        const inst2 = new CustomClass( 'test' );

        expect( objectHash( inst1 )).not.toBe( objectHash( inst2 ));
        expect( objectHash( inst1 )).toBe( objectHash( inst1 ));
    });

    test( 'should support custom stringify option', () =>
    {
        const obj = { name: 'John', age: 30 };
        const customStringify = ( val: any ) =>
        {
            if( val.name === 'John' )
            {
                return 'special_john';
            }

            return undefined;
        };

        const hashWithCustom = objectHash( obj, { stringify: customStringify });
        const hashWithoutCustom = objectHash( obj );

        expect( hashWithCustom ).not.toBe( hashWithoutCustom );
        expect( objectStringify( obj, { stringify: customStringify } )).toBe( 'special_john' );
    });

    test( 'should support Cyrb64Hash incremental hashing', () =>
    {
        const hasher1 = new Cyrb64Hash();

        hasher1.update( 'hello' );
        hasher1.update( 'world' );

        const hasher2 = new Cyrb64Hash();

        hasher2.update( 'helloworld' );

        expect( hasher1.digest() ).toStrictEqual( hasher2.digest() );

        // Test updateBytes
        const hasher3 = new Cyrb64Hash();

        hasher3.updateBytes( new Uint8Array([ 104, 101, 108, 108, 111 ]) );
        
        const hasher4 = new Cyrb64Hash();

        hasher4.update( 'hello' );

        expect( hasher3.digest() ).toStrictEqual( hasher4.digest() );
    });

    test( 'should hash Symbol values and enumerable Symbol keys on objects', () =>
    {
        const sym = Symbol( 'test' );
        const sym2 = Symbol( 'test' );
        const sym3 = Symbol( 'different' );

        // Symbol values
        expect( objectHash( sym )).toBe( objectHash( sym2 ));
        expect( objectHash( sym )).not.toBe( objectHash( sym3 ));

        // Symbol keys
        const obj1: any = {};
        obj1[sym] = 'value';
        obj1[Symbol( 'another' )] = 'another_value';

        const obj2: any = {};
        obj2[Symbol( 'another' )] = 'another_value';
        obj2[sym2] = 'value';

        expect( objectHash( obj1 )).toBe( objectHash( obj2 ));

        // Symbols are stringified properly
        expect( objectStringify( sym )).toBe( 'Symbol(test)' );
    });

    test( 'should hash ArrayBuffers, TypedArrays, and Buffers by content value', () =>
    {
        const buf1 = Buffer.from([ 1, 2, 3 ]);
        const buf2 = Buffer.from([ 1, 2, 3 ]);
        const buf3 = Buffer.from([ 3, 2, 1 ]);

        expect( objectHash( buf1 )).toBe( objectHash( buf2 ));
        expect( objectHash( buf1 )).not.toBe( objectHash( buf3 ));

        const arrBuf1 = new ArrayBuffer( 4 );
        const arrBuf2 = new ArrayBuffer( 4 );
        new Uint8Array( arrBuf1 ).set([ 1, 2, 3, 4 ]);
        new Uint8Array( arrBuf2 ).set([ 1, 2, 3, 4 ]);

        expect( objectHash( arrBuf1 )).toBe( objectHash( arrBuf2 ));

        const typed1 = new Uint8Array([ 1, 2, 3 ]);
        const typed2 = new Uint8Array([ 1, 2, 3 ]);
        const typed3 = new Int8Array([ 1, 2, 3 ]);

        expect( objectHash( typed1 )).toBe( objectHash( typed2 ));
        // Different types should not collapse/collide
        expect( objectHash( typed1 )).not.toBe( objectHash( typed3 ));

        // Verify stringify representation
        expect( objectStringify( typed1 )).toBe( 'Uint8Array(1,2,3)' );

        const arrCollision1 = [ new Uint8Array([ 1 ]), 2 ];
        const arrCollision2 = [ new Uint8Array([ 1, 2 ]) ];
        expect( objectHash( arrCollision1 )).not.toBe( objectHash( arrCollision2 ));
        expect( objectStringify( arrCollision1 )).not.toBe( objectStringify( arrCollision2 ));

        // Check if array with undefined collides with empty array
        expect( objectHash([ undefined ])).not.toBe( objectHash([]));

        // Verify Set, Map, and sorted Array stringify representations
        const setVal = new Set([ 2, 1 ]);
        expect( objectStringify( setVal )).toBe( 'Set(1,2)' );

        const mapVal = new Map([[ 2, 'b' ], [ 1, 'a' ]]);
        expect( objectStringify( mapVal )).toBe( 'Map(1:"a",2:"b")' );

        const arrVal = [ 2, 1 ];
        expect( objectStringify( arrVal, { sortArrays: true } )).toBe( '[1,2]' );

        // Verify larger bit lengths for binary data to test all unrolled updateBytes loops
        expect( objectHash( buf1, { bitLength: 128 } ).length ).toBe( 28 );
        expect( objectHash( buf1, { bitLength: 192 } ).length ).toBe( 42 );
        expect( objectHash( buf1, { bitLength: 256 } ).length ).toBe( 56 );
    });

    test( 'should hash functions by their reference identity', () =>
    {
        const fn1 = () => 'test';
        const fn2 = () => 'test';

        expect( objectHash( fn1 )).toBe( objectHash( fn1 ));
        expect( objectHash( fn1 )).not.toBe( objectHash( fn2 ));
        expect( objectStringify( fn1 )).toContain( 'function fn1' );
        expect( objectStringify( () => 'test' )).toContain( 'function anonymous' );
        
        function namedFn() { return 1; }
        expect( objectStringify( namedFn )).toContain( 'function namedFn' );
    });

    test( 'should support custom bitLength configuration (64, 96, 128, 192, 256)', () =>
    {
        const obj = { message: 'hello world', nested: { val: 42 } };

        const hash64 = objectHash( obj, { bitLength: 64 });
        const hash96 = objectHash( obj, { bitLength: 96 });
        const hash128 = objectHash( obj, { bitLength: 128 });
        const hash192 = objectHash( obj, { bitLength: 192 });
        const hash256 = objectHash( obj, { bitLength: 256 });

        // Verify string lengths
        expect( hash64.length ).toBe( 14 );
        expect( hash96.length ).toBe( 21 );
        expect( hash128.length ).toBe( 28 );
        expect( hash192.length ).toBe( 42 );
        expect( hash256.length ).toBe( 56 );

        // Verify prefix inheritance
        expect( hash96.startsWith( hash64 )).toBe( true );
        expect( hash128.startsWith( hash96 )).toBe( true );
        expect( hash192.startsWith( hash128 )).toBe( true );
        expect( hash256.startsWith( hash192 )).toBe( true );

        // Verify incremental hasher outputs match
        const hasher = new Cyrb64Hash( 256 );

        hasher.update( 'hello' );

        const digest256 = hasher.digest();

        const hasher96 = new Cyrb64Hash( 96 );

        hasher96.update( 'hello' );

        const digest96 = hasher96.digest();

        expect( digest256.subarray( 0, 12 )).toStrictEqual( digest96 );
        expect( digest96.length ).toBe( 12 );
    });

    test( 'should correctly format Uint8Array to base-36 string using bytesToBase36', () =>
    {
        const bytes = new Uint8Array([ 0, 0, 0, 42, 0, 0, 0, 100 ]);
        const str = bytesToBase36( bytes );

        expect( str ).toBe( '0000016000002s' );
    });

    test( 'should support MurmurHash3 incremental hashing and updateBytes', () =>
    {
        const hasher1 = new MurmurHash3();

        hasher1.update( 'hello' );
        hasher1.update( 'world' );

        const hasher2 = new MurmurHash3();

        hasher2.update( 'helloworld' );

        expect( hasher1.digest() ).toStrictEqual( hasher2.digest() );

        const hasher3 = new MurmurHash3();

        hasher3.updateBytes( new Uint8Array([ 104, 101, 108, 108, 111 ]) );

        const hasher4 = new MurmurHash3();

        hasher4.update( 'hello' );

        expect( hasher3.digest() ).toStrictEqual( hasher4.digest() );
    });

    test( 'should support MurmurHash3 custom bitLength configuration and prefix inheritance', () =>
    {
        const obj = { message: 'hello world', nested: { val: 42 } };

        const hash64 = objectHash( obj, { algorithm: 'murmur3', bitLength: 64 });
        const hash96 = objectHash( obj, { algorithm: 'murmur3', bitLength: 96 });
        const hash128 = objectHash( obj, { algorithm: 'murmur3', bitLength: 128 });
        const hash192 = objectHash( obj, { algorithm: 'murmur3', bitLength: 192 });
        const hash256 = objectHash( obj, { algorithm: 'murmur3', bitLength: 256 });

        // Verify string lengths
        expect( hash64.length ).toBe( 14 );
        expect( hash96.length ).toBe( 21 );
        expect( hash128.length ).toBe( 28 );
        expect( hash192.length ).toBe( 42 );
        expect( hash256.length ).toBe( 56 );

        // Verify prefix inheritance
        expect( hash96.startsWith( hash64 )).toBe( true );
        expect( hash128.startsWith( hash96 )).toBe( true );
        expect( hash192.startsWith( hash128 )).toBe( true );
        expect( hash256.startsWith( hash192 )).toBe( true );

        // Verify incremental hasher outputs match
        const hasher = new MurmurHash3( 256 );

        hasher.update( 'hello' );

        const digest256 = hasher.digest();

        const hasher96 = new MurmurHash3( 96 );

        hasher96.update( 'hello' );

        const digest96 = hasher96.digest();

        expect( digest256.subarray( 0, 12 )).toStrictEqual( digest96 );
        expect( digest96.length ).toBe( 12 );
    });

    test( 'should hash Sets and Maps deterministically with MurmurHash3 regardless of order', () =>
    {
        const set1 = new Set([ { id: 2 }, { id: 1 } ]);
        const set2 = new Set([ { id: 1 }, { id: 2 } ]);

        expect( objectHash( set1, { algorithm: 'murmur3' } )).toBe( objectHash( set2, { algorithm: 'murmur3' } ));

        const map1 = new Map();
        map1.set( { id: 2 }, 'two' );
        map1.set( { id: 1 }, 'one' );

        const map2 = new Map();
        map2.set( { id: 1 }, 'one' );
        map2.set( { id: 2 }, 'two' );

        expect( objectHash( map1, { algorithm: 'murmur3' } )).toBe( objectHash( map2, { algorithm: 'murmur3' } ));
    });

    test( 'should support passing any custom hasher factory or instance (e.g. Node crypto)', () =>
    {
        const crypto = require( 'crypto' );
        const obj = { message: 'hello world', sub: { a: 1, b: 2 }, binary: new Uint8Array([ 1, 2, 3 ]) };

        // Test passing a factory function
        const hashFactory = objectHash( obj, { hasher: () => crypto.createHash( 'sha256' ) });

        expect( typeof hashFactory ).toBe( 'string' );
        expect( hashFactory.length ).toBeGreaterThan( 20 );

        // Test passing a pre-created instance
        const hashInstance = objectHash( obj, { hasher: crypto.createHash( 'sha256' ) });

        expect( hashInstance ).toBe( hashFactory );

        // Test passing a pre-created instance without copy method
        const dummyInstance = {
            buf: '',
            update( str: string | Uint8Array )
            {
                this.buf += str.toString();
            },
            digest()
            {
                return 'dummy_digest';
            }
        };

        const hashDummy = objectHash( obj, { hasher: dummyInstance });

        expect( hashDummy ).toBe( 'dummy_digest' );

        // Test passing primitive value to hasher (covers default fallback)
        const hashNull = objectHash( obj, { hasher: 42 });

        expect( hashNull ).toBeDefined();

        // Test determinism with Set/Map sorting under the custom hasher
        const set1 = new Set([ { id: 2 }, { id: 1 } ]);
        const set2 = new Set([ { id: 1 }, { id: 2 } ]);

        const hSet1 = objectHash( set1, { hasher: () => crypto.createHash( 'sha256' ) });
        const hSet2 = objectHash( set2, { hasher: () => crypto.createHash( 'sha256' ) });

        expect( hSet1 ).toBe( hSet2 );
    });

    test( 'should support passing sha256 to algorithm or hasher option directly and support aliases', () =>
    {
        const obj = { message: 'hello world', sub: { a: 1, b: 2 } };

        // Test passing algorithm: 'sha256'
        const hashAlg = objectHash( obj, { algorithm: 'sha256' });

        expect( typeof hashAlg ).toBe( 'string' );
        expect( hashAlg.length ).toBeGreaterThan( 20 );

        // Test passing hasher: 'sha256'
        const hashHasher = objectHash( obj, { hasher: 'sha256' });

        expect( hashHasher ).toBe( hashAlg );

        // Test aliases mapping
        const hashFast = objectHash( obj, { algorithm: 'fast' });
        const hashCyrb = objectHash( obj, { algorithm: 'cyrb64' });
        const hashDefault = objectHash( obj ); // defaults to fast -> cyrb64

        expect( hashFast ).toBe( hashCyrb );
        expect( hashDefault ).toBe( hashCyrb );

        const hashBalanced = objectHash( obj, { algorithm: 'balanced' });
        const hashMurmur = objectHash( obj, { algorithm: 'murmur3' });

        expect( hashBalanced ).toBe( hashMurmur );

        const hashStrong = objectHash( obj, { algorithm: 'strong' });

        expect( hashStrong ).toBe( hashAlg );

        // Test determinism with Set/Map sorting under the custom algorithm
        const set1 = new Set([ { id: 2 }, { id: 1 } ]);
        const set2 = new Set([ { id: 1 }, { id: 2 } ]);

        const hSet1 = objectHash( set1, { algorithm: 'sha256' });
        const hSet2 = objectHash( set2, { algorithm: 'sha256' });

        expect( hSet1 ).toBe( hSet2 );
    });

    test( 'should throw an error for unsupported algorithm', () =>
    {
        expect( () => objectHash( {}, { algorithm: 'invalid' as any } )).toThrow( 'Unsupported hashing algorithm: invalid' );
    });


    describe( 'Isomorphic converters tests', () =>
    {
        test( 'should encode byte arrays correctly using Buffer when available', () =>
        {
            const testCases = [
                new Uint8Array([]),
                new Uint8Array([ 0 ]),
                new Uint8Array([ 255 ]),
                new Uint8Array([ 1, 2 ]),
                new Uint8Array([ 1, 2, 3 ]),
                new Uint8Array([ 1, 2, 3, 4 ]),
                new Uint8Array([ 1, 2, 3, 4, 5 ]),
                new Uint8Array([ 10, 20, 30, 40, 50, 60, 70, 80 ]),
                new Uint8Array( Array.from( { length: 32 }, ( _, i ) => i ) )
            ];

            for( let i = 0; i < testCases.length; ++i )
            {
                const bytes = testCases[i];

                // Hex
                const hexBuf = Buffer.from( bytes ).toString( 'hex' );
                expect( bytesToHex( bytes )).toBe( hexBuf );

                // Base64
                const b64Buf = Buffer.from( bytes ).toString( 'base64' );
                expect( bytesToBase64( bytes )).toBe( b64Buf );

                // Base64Url
                const b64UrlBuf = Buffer.from( bytes ).toString( 'base64url' );
                expect( bytesToBase64Url( bytes )).toBe( b64UrlBuf );

                // Base36 & Base62 results should be deterministic strings
                expect( typeof bytesToBase36( bytes )).toBe( 'string' );
                expect( typeof bytesToBase62( bytes )).toBe( 'string' );
            }
        });

        test( 'should encode byte arrays identically when Buffer is not available (browser fallback)', () =>
        {
            const testCases = [
                new Uint8Array([]),
                new Uint8Array([ 0 ]),
                new Uint8Array([ 255 ]),
                new Uint8Array([ 1, 2 ]),
                new Uint8Array([ 1, 2, 3 ]),
                new Uint8Array([ 1, 2, 3, 4 ]),
                new Uint8Array([ 1, 2, 3, 4, 5 ]),
                new Uint8Array([ 10, 20, 30, 40, 50, 60, 70, 80 ]),
                new Uint8Array( Array.from( { length: 32 }, ( _, i ) => i ) )
            ];

            const originalBuffer = ( global as any ).Buffer;
            try
            {
                delete ( global as any ).Buffer;

                for( let i = 0; i < testCases.length; ++i )
                {
                    const bytes = testCases[i];

                    // Hex
                    const expectedHex = originalBuffer.from( bytes ).toString( 'hex' );
                    expect( bytesToHex( bytes )).toBe( expectedHex );

                    // Base64
                    const expectedB64 = originalBuffer.from( bytes ).toString( 'base64' );
                    expect( bytesToBase64( bytes )).toBe( expectedB64 );

                    // Base64Url
                    const expectedB64Url = originalBuffer.from( bytes ).toString( 'base64url' );
                    expect( bytesToBase64Url( bytes )).toBe( expectedB64Url );

                    // Base36 & Base62
                    expect( typeof bytesToBase36( bytes )).toBe( 'string' );
                    expect( typeof bytesToBase62( bytes )).toBe( 'string' );
                }
            }
            finally
            {
                ( global as any ).Buffer = originalBuffer;
            }
        });

        test( 'should respect the encoding option in objectHash and objectStringify', () =>
        {
            const obj = { val: 'hello world', number: 12345, list: [ 1, 2, 3 ] };

            const encodings = [ 'hex', 'base36', 'base62', 'base64', 'base64url' ] as const;

            for( let i = 0; i < encodings.length; ++i )
            {
                const encoding = encodings[i];
                const hashVal = objectHash( obj, { encoding } );
                expect( typeof hashVal ).toBe( 'string' );
                expect( hashVal.length ).toBeGreaterThan( 0 );

                // Verify encoding output formats
                if( encoding === 'base64url' )
                {
                    expect( hashVal ).not.toContain( '+' );
                    expect( hashVal ).not.toContain( '/' );
                    expect( hashVal ).not.toContain( '=' );
                }
                else if( encoding === 'hex' )
                {
                    expect( /^[0-9a-f]+$/.test( hashVal )).toBe( true );
                }

                // Verify encodeBytes directly
                const bytes = new Uint8Array([ 1, 2, 3, 4 ]);
                const encoded = encodeBytes( bytes, encoding );
                expect( typeof encoded ).toBe( 'string' );
            }

            // Verify encodeBytes defaults to base36
            const bytes = new Uint8Array([ 1, 2, 3, 4 ]);
            expect( encodeBytes( bytes )).toBe( bytesToBase36( bytes ));
        });
    });

    describe( 'Hasher class tests', () =>
    {
        test( 'should initialize Hasher class with options and call stringify and hash', () =>
        {
            const obj = { b: 2, a: 1 };
            const hasher = new Hasher({ sortArrays: true, encoding: 'hex' });

            // stringify method
            expect( hasher.stringify( obj )).toBe( '{"a":1,"b":2}' );

            // hash method
            const expectedHash = objectHash( obj, { sortArrays: true, encoding: 'hex' });
            expect( hasher.hash( obj )).toBe( expectedHash );
        });
    });

    describe( 'Additional Coverage Tests', () =>
    {
        test( 'should fall back to default serialization if stringify returns undefined', () =>
        {
            const obj = { a: 1, b: 2 };
            const hashVal = objectHash( obj, { stringify: () => undefined } );
            const normalHash = objectHash( obj );
            expect( hashVal ).toBe( normalHash );
        });

        test( 'should deterministically hash objects with Symbol keys', () =>
        {
            const sym1 = Symbol( 'desc1' );
            const sym2 = Symbol( 'desc2' );
            const symNoDesc = Symbol();

            const obj1 = {
                [sym2]: 'value2',
                [sym1]: 'value1',
                [symNoDesc]: 'nodesc',
                normalKey: 'normal'
            };

            const obj2 = {
                [symNoDesc]: 'nodesc',
                normalKey: 'normal',
                [sym2]: 'value2',
                [sym1]: 'value1'
            };

            expect( objectHash( obj1 ) ).toBe( objectHash( obj2 ) );

            const stringified = objectStringify( obj1 );
            expect( stringified ).toContain( 'Symbol(desc1)' );
            expect( stringified ).toContain( 'Symbol(desc2)' );
            expect( stringified ).toContain( 'Symbol()' );
        });

        test( 'should support native crypto algorithms and throw on unsupported algorithms', () =>
        {
            const obj = { test: 'data' };

            const hashSha = objectHash( obj, { algorithm: 'sha256' } );
            const hashStrong = objectHash( obj, { algorithm: 'strong' } );
            expect( hashSha ).toBe( hashStrong );

            expect( () => objectHash( obj, { algorithm: 'unknown' } ) ).toThrowError( 'Unsupported hashing algorithm: unknown' );
        });

        test( 'MurmurHash3 should handle empty string/bytes updates', () =>
        {
            const hasher = new MurmurHash3();
            hasher.update( '' );
            hasher.updateBytes( new Uint8Array() );
            const digest = hasher.digest();
            expect( digest ).toBeInstanceOf( Uint8Array );
            expect( digest.length ).toBe( 8 );
        });

        test( 'MurmurHash3 should process all tail sizes (1 to 15 bytes) correctly', () =>
        {
            for( let len = 1; len <= 15; ++len )
            {
                const bytes = new Uint8Array( len );
                for ( let i = 0; i < len; ++i ) { bytes[i] = i + 1; }

                const hasher = new MurmurHash3( 128 );
                hasher.updateBytes( bytes );
                const digest = hasher.digest();

                expect( digest.length ).toBe( 16 );
            }
        });

        test( 'should respect custom toJSON methods on plain objects and custom class instances', () =>
        {
            const objWithToJSON = {
                a: 1,
                toJSON: () => ( { custom: 'serialized' } )
            };

            class CustomClassWithToJSON
            {
                toJSON()
                {
                    return 'customString';
                }
            }

            expect( objectStringify( objWithToJSON ) ).toBe( '{"custom":"serialized"}' );
            expect( objectStringify( new CustomClassWithToJSON() ) ).toBe( '"customString"' );
        });

        test( 'should support boxed Symbols by value rather than reference', () =>
        {
            const boxedSym1 = Object( Symbol( 'description' ) );
            const boxedSym2 = Object( Symbol( 'description' ) );

            expect( objectStringify( boxedSym1 ) ).toBe( 'Symbol(description)' );
            expect( objectHash( boxedSym1 ) ).toBe( objectHash( boxedSym2 ) );
        });

        test( 'should serialize and hash URLSearchParams by value', () =>
        {
            const params1 = new URLSearchParams( 'a=1&b=2' );
            const params2 = new URLSearchParams( 'a=1&b=2' );
            const params3 = new URLSearchParams( 'a=2&b=3' );

            expect( objectStringify( params1 ) ).toBe( 'URLSearchParams(a=1&b=2)' );
            expect( objectHash( params1 ) ).toBe( objectHash( params2 ) );
            expect( objectHash( params1 ) ).not.toBe( objectHash( params3 ) );
        });

        test( 'should sort Symbol keys deterministically even with identical descriptions', () =>
        {
            const sym1 = Symbol( 'same' );
            const sym2 = Symbol( 'same' );

            const obj1 = {
                [sym2]: 'value2',
                [sym1]: 'value1'
            };

            const obj2 = {
                [sym1]: 'value1',
                [sym2]: 'value2'
            };

            expect( objectHash( obj1 ) ).toBe( objectHash( obj2 ) );
        });

        test( 'should sort Symbol keys deterministically regardless of other symbols hashed prior in the process', () =>
        {
            const otherSym = Symbol( 'same' );
            objectHash( { [otherSym]: 'other' } );

            const sym1 = Symbol( 'same' );
            const sym2 = Symbol( 'same' );

            const obj1 = {
                [sym2]: 'value2',
                [sym1]: 'value1'
            };

            const obj2 = {
                [sym1]: 'value1',
                [sym2]: 'value2'
            };

            expect( objectHash( obj1 ) ).toBe( objectHash( obj2 ) );
        });

        test( 'should hash references deterministically in the same process regardless of other objects hashed prior', () =>
        {
            const fn = () => {};
            const hash1 = objectHash( { f: fn } );

            objectHash( { f: () => {} } );
            objectHash( { f: () => {} } );

            const hash2 = objectHash( { f: fn } );
            expect( hash1 ).toBe( hash2 );
        });

        test( 'randomID should fall back to Node crypto and Math.random if Web Crypto is unavailable', () =>
        {
            const originalCrypto = (globalThis as any).crypto;

            try
            {
                delete (globalThis as any).crypto;

                const fn1 = () => {};
                const hash1 = objectHash( { f: fn1 } );
                expect( typeof hash1 ).toBe( 'string' );

                const nodeCrypto = require( 'crypto' );
                const originalRandomBytes = nodeCrypto.randomBytes;
                try
                {
                    nodeCrypto.randomBytes = undefined;

                    const fn2 = () => {};
                    const hash2 = objectHash( { f: fn2 } );
                    expect( typeof hash2 ).toBe( 'string' );
                }
                finally
                {
                    nodeCrypto.randomBytes = originalRandomBytes;
                }
            }
            finally
            {
                (globalThis as any).crypto = originalCrypto;
            }
        });

    describe( 'excludeKeys option', () =>
    {
        test( 'should exclude specified keys at top level', () =>
        {
            const obj = { a: 1, b: 2, _id: 'abc', updatedAt: 12345 };
            const hash1 = objectHash( obj, { excludeKeys: ['_id', 'updatedAt'] } );
            const hash2 = objectHash( { a: 1, b: 2 } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should exclude keys recursively in nested objects', () =>
        {
            const obj = { a: 1, nested: { b: 2, _id: 'inner' } };
            const hash1 = objectHash( obj, { excludeKeys: ['_id'] } );
            const hash2 = objectHash( { a: 1, nested: { b: 2 } } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should not affect Symbol keys', () =>
        {
            const sym = Symbol( 'keep' );
            const obj = { _id: 'skip', [sym]: 'value' };
            const hash1 = objectHash( obj, { excludeKeys: ['_id'] } );

            expect( typeof hash1 ).toBe( 'string' );
            expect( hash1.length ).toBeGreaterThan( 0 );
        });
    });

    describe( 'includeKeys option', () =>
    {
        test( 'should include only specified keys at top level', () =>
        {
            const obj = { a: 1, b: 2, c: 3, d: 4 };
            const hash1 = objectHash( obj, { includeKeys: ['a', 'b'] } );
            const hash2 = objectHash( { a: 1, b: 2 } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should include keys recursively in nested objects', () =>
        {
            const obj = { a: 1, nested: { b: 2, c: 3 } };
            const hash1 = objectHash( obj, { includeKeys: ['a', 'nested', 'b'] } );
            const hash2 = objectHash( { a: 1, nested: { b: 2 } } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should take precedence over excludeKeys when both are specified', () =>
        {
            const obj = { a: 1, b: 2, c: 3 };
            const hash1 = objectHash( obj, { includeKeys: ['a', 'b'], excludeKeys: ['a'] } );
            const hash2 = objectHash( { a: 1, b: 2 } );

            expect( hash1 ).toBe( hash2 );
        });
    });

    describe( 'excludeValues option', () =>
    {
        test( 'should hash only the object shape when excludeValues is true', () =>
        {
            const obj1 = { a: 1, b: 'hello', c: true };
            const obj2 = { a: 999, b: 'world', c: false };
            const hash1 = objectHash( obj1, { excludeValues: true } );
            const hash2 = objectHash( obj2, { excludeValues: true } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should produce different hashes for different shapes', () =>
        {
            const obj1 = { a: 1, b: 2 };
            const obj2 = { a: 1, c: 2 };
            const hash1 = objectHash( obj1, { excludeValues: true } );
            const hash2 = objectHash( obj2, { excludeValues: true } );

            expect( hash1 ).not.toBe( hash2 );
        });

        test( 'should apply recursively to nested objects', () =>
        {
            const obj1 = { a: { b: 1 } };
            const obj2 = { a: { b: 999 } };
            const hash1 = objectHash( obj1, { excludeValues: true } );
            const hash2 = objectHash( obj2, { excludeValues: true } );

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should work with objectStringify', () =>
        {
            const str1 = objectStringify( { a: 1, b: 2 }, { excludeValues: true } );
            const str2 = objectStringify( { a: 100, b: 200 }, { excludeValues: true } );

            expect( str1 ).toBe( str2 );
        });
    });

    describe( 'Promise handling', () =>
    {
        test( 'should serialize Promise as Promise(pending)', () =>
        {
            const p = new Promise( () => {} );
            const str = objectStringify( p );

            expect( str ).toBe( 'Promise(pending)' );
        });

        test( 'should produce identical hashes for different Promises', () =>
        {
            const p1 = new Promise( () => {} );
            const p2 = Promise.resolve( 42 );

            expect( objectHash( p1 ) ).toBe( objectHash( p2 ) );
        });
    });

    describe( 'WeakRef / WeakMap / WeakSet handling', () =>
    {
        test( 'should hash WeakRef by dereferencing its target', () =>
        {
            const target = { x: 42 };
            const ref = new WeakRef( target );
            const str = objectStringify( ref );

            expect( str ).toBe( 'WeakRef(' + objectStringify( target ) + ')' );
        });

        test( 'should serialize WeakMap as opaque', () =>
        {
            const wm = new WeakMap();
            wm.set( {}, 'value' );
            const str = objectStringify( wm );

            expect( str ).toBe( 'WeakMap(opaque)' );
        });

        test( 'should serialize WeakSet as opaque', () =>
        {
            const ws = new WeakSet();
            ws.add( {} );
            const str = objectStringify( ws );

            expect( str ).toBe( 'WeakSet(opaque)' );
        });

        test( 'should produce identical hashes for different WeakMaps', () =>
        {
            const wm1 = new WeakMap();
            const wm2 = new WeakMap();
            wm1.set( {}, 'a' );
            wm2.set( {}, 'b' );

            expect( objectHash( wm1 ) ).toBe( objectHash( wm2 ) );
        });

        test( 'should produce identical hashes for different WeakSets', () =>
        {
            const ws1 = new WeakSet();
            const ws2 = new WeakSet();
            ws1.add( {} );
            ws2.add( {} );

            expect( objectHash( ws1 ) ).toBe( objectHash( ws2 ) );
        });
    });

    describe( 'objectHashBytes', () =>
    {
        test( 'should return a Uint8Array', () =>
        {
            const result = objectHashBytes( { a: 1, b: 2 } );

            expect( result ).toBeInstanceOf( Uint8Array );
            expect( result.length ).toBeGreaterThan( 0 );
        });

        test( 'should return same bytes for same input', () =>
        {
            const bytes1 = objectHashBytes( { x: 'hello' } );
            const bytes2 = objectHashBytes( { x: 'hello' } );

            expect( bytes1 ).toEqual( bytes2 );
        });

        test( 'should return different bytes for different input', () =>
        {
            const bytes1 = objectHashBytes( { a: 1 } );
            const bytes2 = objectHashBytes( { b: 2 } );

            expect( bytes1 ).not.toEqual( bytes2 );
        });

        test( 'should respect algorithm and bitLength options', () =>
        {
            const bytes64 = objectHashBytes( 'test', { algorithm: 'cyrb64', bitLength: 64 } );
            const bytes128 = objectHashBytes( 'test', { algorithm: 'murmur3', bitLength: 128 } );

            expect( bytes64.length ).toBe( 8 );
            expect( bytes128.length ).toBe( 16 );
        });
    });

    describe( 'StreamingHash API', () =>
    {
        test( 'should support chained update().digest()', () =>
        {
            const stream = new StreamingHash();
            const result = stream.update( 'hello' ).update( 42 ).digest();

            expect( typeof result ).toBe( 'string' );
            expect( result.length ).toBeGreaterThan( 0 );
        });

        test( 'should support Hasher.prototype.createHash() to reuse configured options', () =>
        {
            const hasher = new Hasher( { algorithm: 'murmur3', encoding: 'hex', bitLength: 128 } );
            const stream = hasher.createHash();
            const result = stream.update( 'hello' ).update( 42 ).digest();

            expect( typeof result ).toBe( 'string' );
            // A 128-bit MurmurHash3 hex digest has 32 characters
            expect( result.length ).toBe( 32 );
        });

        test( 'should support standalone new StreamingHash() construction', () =>
        {
            const stream = new StreamingHash( { algorithm: 'cyrb64' } );
            const result = stream.update( 'hello' ).digest();

            expect( typeof result ).toBe( 'string' );
            expect( result.length ).toBeGreaterThan( 0 );
        });

        test( 'should support digestBytes()', () =>
        {
            const stream = new StreamingHash();
            const bytes = stream.update( { x: 1 } ).digestBytes();

            expect( bytes ).toBeInstanceOf( Uint8Array );
            expect( bytes.length ).toBeGreaterThan( 0 );
        });

        test( 'should support reset() to clear state', () =>
        {
            const stream = new StreamingHash();
            const hash1 = stream.update( 'a' ).digest();

            stream.reset();
            stream.update( 'a' );
            const hash2 = stream.digest();

            expect( hash1 ).toBe( hash2 );
        });

        test( 'should produce different digests for different update sequences', () =>
        {
            const s1 = new StreamingHash();
            const s2 = new StreamingHash();

            const result1 = s1.update( 'a' ).update( 'b' ).digest();
            const result2 = s2.update( 'b' ).update( 'a' ).digest();

            expect( result1 ).not.toBe( result2 );
        });

        test( 'should respect options passed to constructor', () =>
        {
            const s1 = new StreamingHash( { algorithm: 'murmur3' } );
            const s2 = new StreamingHash( { algorithm: 'cyrb64' } );

            const result1 = s1.update( 'test' ).digest();
            const result2 = s2.update( 'test' ).digest();

            expect( result1 ).not.toBe( result2 );
        });
    });

    describe( 'Golden Stability Snapshots', () =>
    {
        test( 'should match precalculated hashes for all algorithms', () =>
        {
            const sym = Symbol( 'test-symbol' );
            const symNoDesc = Symbol();
            const symSame1 = Symbol( 'same' );
            const symSame2 = Symbol( 'same' );

            const objWithToJSON = {
                a: 1,
                toJSON: () => ( { custom: 'serialized' } )
            };

            class CustomClassWithToJSON
            {
                toJSON()
                {
                    return 'customString';
                }
            }

            const cases = [
                { name: 'undefined', val: undefined, expected: { cyrb64: "1vgkz5t0s0bvwg", murmur3: "1v3j3q00ldw810", sha256: "1t7ipo81me4cxf0k628zw00i7fcl0mzfhrf1ga8jnl1dx7ad116wvocs" } },
                { name: 'null', val: null, expected: { cyrb64: "173lp0a0teocvu", murmur3: "0qwstkr0kprbas", sha256: "0w82hso1ct1tov1egi1v70tmenbe1knpmck1x6bvwb12uheaa1x8aiob" } },
                { name: 'true', val: true, expected: { cyrb64: "02dqmoc11gxzhw", murmur3: "1fzvtbe13c45u8", sha256: "1efeal70u2m5j002rbx2c1p8bkkr1biex251455d2j1ig29pw0k38oiz" } },
                { name: 'false', val: false, expected: { cyrb64: "1921dai0rmnlwq", murmur3: "0wbf7o6110od1u", sha256: "1y4j2w5143wqkq17x3qwv0ayldh21ox3exv1e01jpv0w7kco40msimy2" } },
                { name: 'hello', val: 'hello', expected: { cyrb64: "0lmgqi316zrmjn", murmur3: "0l9eze91k5g9cr", sha256: "0p5ikry0flus8i0y44w4j0ubmmxx1f9kntk155k8q80m4yqyn0hjdapm" } },
                { name: 'empty_string', val: '', expected: { cyrb64: "1c6ccqh13d2div", murmur3: "1v2flfk0foie5a", sha256: "056ldqj08j5rep1txp7ob054n1m60gdvdx10vvz7hr09vi2sg0h2f2na" } },
                { name: 'number_42', val: 42, expected: { cyrb64: "19xu4oo0ufs8xb", murmur3: "085a4f10zardjm", sha256: "0vzhjn802v9itp1ascwy61m09pxa05zzkei1imbdq30tpq2jp07jz7m1" } },
                { name: 'number_neg_pi', val: -3.14, expected: { cyrb64: "02nx0440iortjl", murmur3: "037jjje0gkym84", sha256: "0tnh1oh0yuf9q51eanbl51l2fi0x0fcstvb15xp5fs0qqqsho1dwasd5" } },
                { name: 'number_nan', val: NaN, expected: { cyrb64: "10fs7xl1bocpqa", murmur3: "1ry1eb31nbr8il", sha256: "1naokao0q0j8sw0dyrfvf0b330d71sr26fz0w597lc0bxqi3k1idjf32" } },
                { name: 'number_inf', val: Infinity, expected: { cyrb64: "1tm2jz21hh9vrl", murmur3: "05pu92w1fngd7i", sha256: "1lpwnn116u5ri90fcvkqj10n5bre0w03kst196xnd002xge3h1eohk40" } },
                { name: 'number_neg_inf', val: -Infinity, expected: { cyrb64: "11quh3l0meussy", murmur3: "1rg66rj1voh0s5", sha256: "1j0szkh1ge5xeo1utdvq503d81is0o5loer1y13rmx1abr8ki1cjsugp" } },
                { name: 'bigint', val: 12345678901234567890n, expected: { cyrb64: "17m3f3u16dpbcs", murmur3: "1ticdjr09vs3q1", sha256: "1bsatrz1y2ogoi0lhglnv0fxnza40er1y8m1a4ylda0ymv1y9095kmpg" } },
                { name: 'symbol_desc', val: sym, expected: { cyrb64: "0x74yb21x9o2fm", murmur3: "0ir3wpr0nnnrhv", sha256: "14eqxc51cpi4w107uo68i1srd1jz1horjcp1ks7o0a1xscv831pvmweg" } },
                { name: 'symbol_nodesc', val: symNoDesc, expected: { cyrb64: "0knoslw1icfbxc", murmur3: "0kssa961mi377q", sha256: "16pjn3f1x6t7zv05s8wdb06t4jw00emrfr11v3ykto0ljbc501d8xxfd" } },
                { name: 'plain_object', val: { a: 1, b: 2 }, expected: { cyrb64: "0807dix0nd8pir", murmur3: "1xicw9w1nb8vqh", sha256: "0impji70xd51c30ue5ybn0hmehnj1iycbp30fksgno12i7v0811s2l4n" } },
                { name: 'plain_object_alt_order', val: { b: 2, a: 1 }, expected: { cyrb64: "0807dix0nd8pir", murmur3: "1xicw9w1nb8vqh", sha256: "0impji70xd51c30ue5ybn0hmehnj1iycbp30fksgno12i7v0811s2l4n" } },
                { name: 'nested_object', val: { x: { y: { z: 3 } } }, expected: { cyrb64: "0vbcxod067sg8o", murmur3: "16zy3h30w39vrs", sha256: "1n5qamz0gjjnwj1n73j2o1og2qk01r7kj6o1k4obq210m2u8a162lzuo" } },
                { name: 'array', val: [3, 2, 1], expected: { cyrb64: "1ngawjh1lcs9am", murmur3: "1rx8ove05ko5yl", sha256: "0dja0in175ejf21u4p6471vm665q0su23zr08394gr10dr37l0m4d759" } },
                { name: 'set', val: new Set([2, 1]), expected: { cyrb64: "19a2ne31e7rfvx", murmur3: "14ez9wd17368tw", sha256: "1mo6r7p0w8haz71d6try90tlut4x0ldsc5v103i36p1p6m1np0nrb0gn" } },
                { name: 'map', val: new Map([['b', 2], ['a', 1]]), expected: { cyrb64: "085w1ts08qph9y", murmur3: "1btive01qe3w75", sha256: "0m37czj1mttumu0l972o11jny60j0clg0xr0vgij8f11w6g521gxr8eg" } },
                { name: 'boxed_string', val: new String("boxed"), expected: { cyrb64: "11pj9yr12dogiw", murmur3: "1wxr1xf07mwow8", sha256: "0m10n690scutva1tn9nxk15xlrva015732r0b2vwnz1vt73zl0fddftn" } },
                { name: 'boxed_number', val: new Number(123), expected: { cyrb64: "1gnpfzd0a466hr", murmur3: "1g3shfm0b1853x", sha256: "1a63dcp08y7z4t0i66zqf1ujwf5k18h35fj1yscvwe16lu2uv1wpjxsz" } },
                { name: 'boxed_boolean', val: new Boolean(true), expected: { cyrb64: "02dqmoc11gxzhw", murmur3: "1fzvtbe13c45u8", sha256: "1efeal70u2m5j002rbx2c1p8bkkr1biex251455d2j1ig29pw0k38oiz" } },
                { name: 'boxed_symbol', val: Object(Symbol("boxed-symbol")), expected: { cyrb64: "06rch0g1ij1a7k", murmur3: "0ddsfzj0yx0mrm", sha256: "0ted84n1d1xc9m00qxn20045sx5b0csvaxx0zt42680jk6nyg1lnhy5u" } },
                { name: 'date', val: new Date("2026-07-20T07:20:00.000Z"), expected: { cyrb64: "0hp1u7s10i6a41", murmur3: "1d1pnkd0kueowz", sha256: "0o8zn8m1b6hb5a19m4xlb074nvlz0hqp0980kik5en182obkh018yr22" } },
                { name: 'regexp', val: /abc/gi, expected: { cyrb64: "05gtibu0nn8vlh", murmur3: "1awf9dk1fm1fqp", sha256: "04fybqt1o6h8ze07p0fdu0yxslsy1yrtxkr0b3qxqh06854rp1o8v5ee" } },
                { name: 'error', val: new Error("error message"), expected: { cyrb64: "1lci1tq026dh6q", murmur3: "0j6tdy30iku9sf", sha256: "0i4g03m1gbr9e80j45mwg18h3o6w0gbno7f0n2voh60x7zvkx06h97ep" } },
                { name: 'url', val: new URL("https://example.com/foo"), expected: { cyrb64: "0mgl7mt0qkcdaq", murmur3: "04yruty0fc7wwd", sha256: "07qio3h03f3du81ekp3qw1t2go5e10n83960wqq43j1mi160r1d8bbcw" } },
                { name: 'url_search_params', val: new URLSearchParams("x=1&y=2"), expected: { cyrb64: "1ep8h9q0fen8j7", murmur3: "193ipwp1p1bcjr", sha256: "11iqdif0v3r7li0nl3jby1tfypg90st11su1czoos20ackwgo1tvgms3" } },
                { name: 'to_json_object', val: objWithToJSON, expected: { cyrb64: "1s5l3750vqmfvd", murmur3: "0l1yxag0267ykv", sha256: "04a4b9v1a9cf8h0ylmb840me0eit102w1mf00jtqz90z7dby60byaqlt" } },
                { name: 'to_json_class', val: new CustomClassWithToJSON(), expected: { cyrb64: "0nff2yo07xxjcc", murmur3: "1bek8131a3op2o", sha256: "14kw3n01nj8uzi087mi9y1y1lx631wmfs9513hgra715dqq650nwzw26" } },
                { name: 'uint8array', val: new Uint8Array([1, 2, 3]), expected: { cyrb64: "196yq0x16chz2d", murmur3: "04gsodb14eekt2", sha256: "1rohx7910zm35y1klte7s16ggn0l0830uvh1ega6wt0ljts3a18oe338" } },
                { name: 'duplicate_symbols', val: { [symSame2]: 'v2', [symSame1]: 'v1' }, expected: { cyrb64: "1ga2ckb0asa324", murmur3: "0bd13591np8o73", sha256: "1q48ef000mxopz1hv9ix50jjm1oc1qvf04j0saib3e1s5w4mf08or37k" } },
                { name: 'nested_array_of_objects', val: [ { a: 1, b: [ 2, 3 ] }, { c: { d: 4 } } ], expected: { cyrb64: "1h8sk5h0yvwomq", murmur3: "16fy6b60uj3ckd", sha256: "0ncebj90cwa2t20ndzptk0iihs9r0ww7jfl1gdhuyi1j9z7w2194vaa1" } },
                { name: 'deep_mixed_structure', val: { a: [ { x: 1 } ], b: new Map([ [ 'key', { nested: [ 1, 2 ] } ] ]) }, expected: { cyrb64: "0uaetg904lm5db", murmur3: "1ud28yf1c8d48i", sha256: "0ijbenb06qi5fp1noc5541tu1ma8161wen41bnpyfv0gdbunu1py4i5t" } },
                { name: 'complex_nested_json', val: { user: { id: 123, profile: { name: 'John', tags: ['admin', 'user'] } }, meta: { status: 'active' } }, expected: { cyrb64: "0jlaigp07q1oqd", murmur3: "1titmlj1yazro6", sha256: "0j9iq3x1r9y48z0yyzclf1bgqbvq1cwwel60y4fu5o0u5nf9z1rigban" } },
                { name: 'array_of_mixed_types', val: [ 1, 'text', { obj: true }, [ 1, 2 ], new Set([3, 4]) ], expected: { cyrb64: "1yssme10xnidu1", murmur3: "13v6y640ue6hh5", sha256: "0t02bvu1cqq0uy1yismyv1bsp21k1om4ux504i829u0ylx80s0bb1pwk" } }
            ];

            for( const c of cases )
            {
                expect( objectHash( c.val, { algorithm: 'cyrb64' } ) ).toBe( c.expected.cyrb64 );
                expect( objectHash( c.val, { algorithm: 'murmur3' } ) ).toBe( c.expected.murmur3 );
                expect( objectHash( c.val, { algorithm: 'sha256' } ) ).toBe( c.expected.sha256 );
            }
        });
    });
    });
});
