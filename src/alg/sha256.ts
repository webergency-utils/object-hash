import { validateBitLength } from './base';

const ENCODER = new TextEncoder();

const K = new Uint32Array(
[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

const H0 = new Uint32Array(
[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

export default class Sha256Hash
{
    #state: Uint32Array;
    #buffer = new Uint8Array( 64 );
    #w = new Uint32Array( 64 );
    #bufLen = 0;
    #totalLen = 0;
    #bitLength: 64 | 96 | 128 | 192 | 256;

    constructor( bitLength: 64 | 96 | 128 | 192 | 256 = 256 )
    {
        validateBitLength( bitLength );

        this.#bitLength = bitLength;
        this.#state = new Uint32Array( H0 );
    }

    #compress( state: Uint32Array, block: Uint8Array, offset: number )
    {
        const w = this.#w;

        for( let i = 0; i < 16; ++i )
        {
            const j = offset + ( i * 4 );
            w[i] = (
                ( block[j] << 24 ) |
                ( block[j + 1] << 16 ) |
                ( block[j + 2] << 8 ) |
                ( block[j + 3] )
            ) >>> 0;
        }

        for( let i = 16; i < 64; ++i )
        {
            const w15 = w[i - 15];
            const s0 = ((( w15 >>> 7 ) | ( w15 << 25 )) ^ (( w15 >>> 18 ) | ( w15 << 14 )) ^ ( w15 >>> 3 )) >>> 0;
            const w2 = w[i - 2];
            const s1 = ((( w2 >>> 17 ) | ( w2 << 15 )) ^ (( w2 >>> 19 ) | ( w2 << 13 )) ^ ( w2 >>> 10 )) >>> 0;

            w[i] = ( w[i - 16] + s0 + w[i - 7] + s1 ) >>> 0;
        }

        let a = state[0];
        let b = state[1];
        let c = state[2];
        let d = state[3];
        let e = state[4];
        let f = state[5];
        let g = state[6];
        let h = state[7];

        for( let i = 0; i < 64; ++i )
        {
            const S1 = ((( e >>> 6 ) | ( e << 26 )) ^ (( e >>> 11 ) | ( e << 21 )) ^ (( e >>> 25 ) | ( e << 7 ))) >>> 0;
            const ch = (( e & f ) ^ (( ~e ) & g )) >>> 0;
            const temp1 = ( h + S1 + ch + K[i] + w[i] ) >>> 0;
            const S0 = ((( a >>> 2 ) | ( a << 30 )) ^ (( a >>> 13 ) | ( a << 19 )) ^ (( a >>> 22 ) | ( a << 10 ))) >>> 0;
            const maj = (( a & b ) ^ ( a & c ) ^ ( b & c )) >>> 0;
            const temp2 = ( S0 + maj ) >>> 0;

            h = g;
            g = f;
            f = e;
            e = ( d + temp1 ) >>> 0;
            d = c;
            c = b;
            b = a;
            a = ( temp1 + temp2 ) >>> 0;
        }

        state[0] = ( state[0] + a ) >>> 0;
        state[1] = ( state[1] + b ) >>> 0;
        state[2] = ( state[2] + c ) >>> 0;
        state[3] = ( state[3] + d ) >>> 0;
        state[4] = ( state[4] + e ) >>> 0;
        state[5] = ( state[5] + f ) >>> 0;
        state[6] = ( state[6] + g ) >>> 0;
        state[7] = ( state[7] + h ) >>> 0;
    }

    update( str: string )
    {
        this.updateBytes( ENCODER.encode( str ));
    }

    updateBytes( bytes: Uint8Array )
    {
        let len = bytes.length;

        if( len === 0 ){ return }

        this.#totalLen += len;

        let offset = 0;

        if( this.#bufLen > 0 )
        {
            const needed = 64 - this.#bufLen;
            const toCopy = Math.min( needed, len );

            this.#buffer.set( bytes.subarray( offset, offset + toCopy ), this.#bufLen );
            this.#bufLen += toCopy;
            offset += toCopy;
            len -= toCopy;

            if( this.#bufLen === 64 )
            {
                this.#compress( this.#state, this.#buffer, 0 );
                this.#bufLen = 0;
            }
        }

        while( len >= 64 )
        {
            this.#compress( this.#state, bytes, offset );
            offset += 64;
            len -= 64;
        }

        if( len > 0 )
        {
            this.#buffer.set( bytes.subarray( offset, offset + len ), 0 );
            this.#bufLen = len;
        }
    }

    digest(): Uint8Array
    {
        const state = new Uint32Array( this.#state );
        const padBlock = new Uint8Array( 64 );
        let padLen = this.#bufLen;

        if( padLen > 0 )
        {
            padBlock.set( this.#buffer.subarray( 0, padLen ), 0 );
        }

        padBlock[padLen++] = 0x80;

        if( padLen > 56 )
        {
            padBlock.fill( 0, padLen, 64 );
            this.#compress( state, padBlock, 0 );
            padBlock.fill( 0, 0, 56 );
        }
        else
        {
            padBlock.fill( 0, padLen, 56 );
        }

        const totalBits = this.#totalLen * 8;
        const highBits = Math.floor( totalBits / 0x100000000 ) >>> 0;
        const lowBits = totalBits >>> 0;

        const padView = new DataView( padBlock.buffer );
        padView.setUint32( 56, highBits, false );
        padView.setUint32( 60, lowBits, false );

        this.#compress( state, padBlock, 0 );

        const fullBytes = new Uint8Array( 32 );
        const outView = new DataView( fullBytes.buffer );

        for( let i = 0; i < 8; ++i )
        {
            outView.setUint32( i * 4, state[i], false );
        }

        const byteLength = this.#bitLength / 8;

        return byteLength === 32 ? fullBytes : fullBytes.slice( 0, byteLength );
    }
}
