import { type BitLength, mixPassSeed, validateBitLength } from './base';

const SEED_H1_0 = mixPassSeed( 0xdeadbeef, 0x9e3779b9, 0 );
const SEED_H2_0 = mixPassSeed( 0x41c6ce57, 0x85ebca6b, 0 );
const SEED_H1_1 = mixPassSeed( 0xdeadbeef, 0x9e3779b9, 1 );
const SEED_H2_1 = mixPassSeed( 0x41c6ce57, 0x85ebca6b, 1 );
const SEED_H1_2 = mixPassSeed( 0xdeadbeef, 0x9e3779b9, 2 );
const SEED_H2_2 = mixPassSeed( 0x41c6ce57, 0x85ebca6b, 2 );
const SEED_H1_3 = mixPassSeed( 0xdeadbeef, 0x9e3779b9, 3 );
const SEED_H2_3 = mixPassSeed( 0x41c6ce57, 0x85ebca6b, 3 );

function finalizePass( bytes: Uint8Array, offset: number, byteLength: number, h1: number, h2: number )
{
    h1  = Math.imul( h1 ^ ( h1 >>> 16 ), 2246822507 );
    h1 ^= Math.imul( h2 ^ ( h2 >>> 13 ), 3266489909 );
    h2  = Math.imul( h2 ^ ( h2 >>> 16 ), 2246822507 );
    h2 ^= Math.imul( h1 ^ ( h1 >>> 13 ), 3266489909 );

    bytes[offset]     = h2 >>> 24;
    bytes[offset + 1] = h2 >>> 16;
    bytes[offset + 2] = h2 >>> 8;
    bytes[offset + 3] = h2;

    if( offset + 4 < byteLength )
    {
        bytes[offset + 4] = h1 >>> 24;
        bytes[offset + 5] = h1 >>> 16;
        bytes[offset + 6] = h1 >>> 8;
        bytes[offset + 7] = h1;
    }
}

export default class Cyrb64Hash
{
    #h1_0      : number = SEED_H1_0;
    #h2_0      : number = SEED_H2_0;
    #h1_1      : number = SEED_H1_1;
    #h2_1      : number = SEED_H2_1;
    #h1_2      : number = SEED_H1_2;
    #h2_2      : number = SEED_H2_2;
    #h1_3      : number = SEED_H1_3;
    #h2_3      : number = SEED_H2_3;
    #passes    : number;
    #bitLength : BitLength;

    constructor( bitLength: BitLength = 64 )
    {
        validateBitLength( bitLength );

        this.#bitLength = bitLength;
        this.#passes = Math.ceil( bitLength / 64 );
    }

    update( str: string )
    {
        const passes = this.#passes;
        const sLen = str.length;
        let h1_0 = this.#h1_0;
        let h2_0 = this.#h2_0;

        if( passes === 1 )
        {
            let i = 0;

            for( ; i + 3 < sLen; i += 4 )
            {
                const c0 = str.charCodeAt( i );
                const c1 = str.charCodeAt( i + 1 );
                const c2 = str.charCodeAt( i + 2 );
                const c3 = str.charCodeAt( i + 3 );

                h1_0 = Math.imul( Math.imul( Math.imul( Math.imul( h1_0 ^ c0, 2654435761 ) ^ c1, 2654435761 ) ^ c2, 2654435761 ) ^ c3, 2654435761 );
                h2_0 = Math.imul( Math.imul( Math.imul( Math.imul( h2_0 ^ c0, 1597334677 ) ^ c1, 1597334677 ) ^ c2, 1597334677 ) ^ c3, 1597334677 );
            }

            for( ; i < sLen; ++i )
            {
                const ch = str.charCodeAt( i );
                h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
                h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );
            }

            this.#h1_0 = h1_0;
            this.#h2_0 = h2_0;

            return;
        }

        let h1_1 = this.#h1_1;
        let h2_1 = this.#h2_1;
        let h1_2 = this.#h1_2;
        let h2_2 = this.#h2_2;
        let h1_3 = this.#h1_3;
        let h2_3 = this.#h2_3;

        for( let i = 0, ch; i < sLen; ++i )
        {
            ch = str.charCodeAt( i );
            h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
            h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );
            h1_1 = Math.imul( h1_1 ^ ch, 2654435761 );
            h2_1 = Math.imul( h2_1 ^ ch, 1597334677 );

            if( passes > 2 )
            {
                h1_2 = Math.imul( h1_2 ^ ch, 2654435761 );
                h2_2 = Math.imul( h2_2 ^ ch, 1597334677 );
            }

            if( passes > 3 )
            {
                h1_3 = Math.imul( h1_3 ^ ch, 2654435761 );
                h2_3 = Math.imul( h2_3 ^ ch, 1597334677 );
            }
        }

        this.#h1_0 = h1_0;
        this.#h2_0 = h2_0;
        this.#h1_1 = h1_1;
        this.#h2_1 = h2_1;
        this.#h1_2 = h1_2;
        this.#h2_2 = h2_2;
        this.#h1_3 = h1_3;
        this.#h2_3 = h2_3;
    }

    updateBytes( bytes: Uint8Array )
    {
        const passes = this.#passes;
        const bLen = bytes.length;
        let h1_0 = this.#h1_0;
        let h2_0 = this.#h2_0;

        if( passes === 1 )
        {
            let i = 0;

            for( ; i + 3 < bLen; i += 4 )
            {
                const c0 = bytes[i];
                const c1 = bytes[i + 1];
                const c2 = bytes[i + 2];
                const c3 = bytes[i + 3];

                h1_0 = Math.imul( Math.imul( Math.imul( Math.imul( h1_0 ^ c0, 2654435761 ) ^ c1, 2654435761 ) ^ c2, 2654435761 ) ^ c3, 2654435761 );
                h2_0 = Math.imul( Math.imul( Math.imul( Math.imul( h2_0 ^ c0, 1597334677 ) ^ c1, 1597334677 ) ^ c2, 1597334677 ) ^ c3, 1597334677 );
            }

            for( ; i < bLen; ++i )
            {
                const ch = bytes[i];
                h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
                h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );
            }

            this.#h1_0 = h1_0;
            this.#h2_0 = h2_0;

            return;
        }

        let h1_1 = this.#h1_1;
        let h2_1 = this.#h2_1;
        let h1_2 = this.#h1_2;
        let h2_2 = this.#h2_2;
        let h1_3 = this.#h1_3;
        let h2_3 = this.#h2_3;

        for( let i = 0, ch; i < bLen; ++i )
        {
            ch = bytes[i];
            h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
            h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );
            h1_1 = Math.imul( h1_1 ^ ch, 2654435761 );
            h2_1 = Math.imul( h2_1 ^ ch, 1597334677 );

            if( passes > 2 )
            {
                h1_2 = Math.imul( h1_2 ^ ch, 2654435761 );
                h2_2 = Math.imul( h2_2 ^ ch, 1597334677 );
            }

            if( passes > 3 )
            {
                h1_3 = Math.imul( h1_3 ^ ch, 2654435761 );
                h2_3 = Math.imul( h2_3 ^ ch, 1597334677 );
            }
        }

        this.#h1_0 = h1_0;
        this.#h2_0 = h2_0;
        this.#h1_1 = h1_1;
        this.#h2_1 = h2_1;
        this.#h1_2 = h1_2;
        this.#h2_2 = h2_2;
        this.#h1_3 = h1_3;
        this.#h2_3 = h2_3;
    }

    digest(): Uint8Array
    {
        const byteLength = this.#bitLength / 8;
        const bytes = new Uint8Array( byteLength );
        const passes = this.#passes;

        finalizePass( bytes, 0, byteLength, this.#h1_0, this.#h2_0 );

        if( passes > 1 )
        {
            finalizePass( bytes, 8, byteLength, this.#h1_1, this.#h2_1 );
        }

        if( passes > 2 )
        {
            finalizePass( bytes, 16, byteLength, this.#h1_2, this.#h2_2 );
        }

        if( passes > 3 )
        {
            finalizePass( bytes, 24, byteLength, this.#h1_3, this.#h2_3 );
        }

        return bytes;
    }
}
