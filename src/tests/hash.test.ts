import 
{ 
    describe, 
    test, 
    expect 
} 
from 'vitest';
import objectHash, { objectStringify, Hasher } from '../hash';
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
});
