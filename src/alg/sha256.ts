import { type BitLength, encodeUtf8, validateBitLength } from './base';

const K = new Int32Array(
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

const W = new Int32Array( 64 );
const PAD_BLOCK = new Uint8Array( 64 );

function writeUint32BE( out: Uint8Array, offset: number, val: number )
{
    out[offset]     = val >>> 24;
    out[offset + 1] = val >>> 16;
    out[offset + 2] = val >>> 8;
    out[offset + 3] = val;
}

export default class Sha256Hash
{
    #h0        : number = 0x6a09e667 | 0;
    #h1        : number = 0xbb67ae85 | 0;
    #h2        : number = 0x3c6ef372 | 0;
    #h3        : number = 0xa54ff53a | 0;
    #h4        : number = 0x510e527f | 0;
    #h5        : number = 0x9b05688c | 0;
    #h6        : number = 0x1f83d9ab | 0;
    #h7        : number = 0x5be0cd19 | 0;
    #buffer = new Uint8Array( 64 );
    #bufLen = 0;
    #totalLen = 0;
    #bitLength : BitLength;

    constructor( bitLength: BitLength = 256 )
    {
        validateBitLength( bitLength );

        this.#bitLength = bitLength;
    }

    #compress( block: Uint8Array, offset: number )
    {
        for( let i = 0; i < 16; ++i )
        {
            const j = offset + ( i << 2 );
            W[i] = (
                ( block[j] << 24 ) |
                ( block[j + 1] << 16 ) |
                ( block[j + 2] << 8 ) |
                ( block[j + 3])
            );
        }

        for( let i = 16; i < 64; ++i )
        {
            const w15 = W[i - 15];
            const s0 = (( w15 >>> 7 ) | ( w15 << 25 )) ^ (( w15 >>> 18 ) | ( w15 << 14 )) ^ ( w15 >>> 3 );
            const w2 = W[i - 2];
            const s1 = (( w2 >>> 17 ) | ( w2 << 15 )) ^ (( w2 >>> 19 ) | ( w2 << 13 )) ^ ( w2 >>> 10 );

            W[i] = ( W[i - 16] + s0 + W[i - 7] + s1 ) | 0;
        }

        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f = this.#h5;
        let g = this.#h6;
        let h = this.#h7;

        for( let i = 0; i < 64; ++i )
        {
            const S1 = (( e >>> 6 ) | ( e << 26 )) ^ (( e >>> 11 ) | ( e << 21 )) ^ (( e >>> 25 ) | ( e << 7 ));
            const ch = ( e & f ) ^ (( ~e ) & g );
            const temp1 = ( h + S1 + ch + K[i] + W[i]) | 0;
            const S0 = (( a >>> 2 ) | ( a << 30 )) ^ (( a >>> 13 ) | ( a << 19 )) ^ (( a >>> 22 ) | ( a << 10 ));
            const maj = ( a & b ) ^ ( a & c ) ^ ( b & c );
            const temp2 = ( S0 + maj ) | 0;

            h = g;
            g = f;
            f = e;
            e = ( d + temp1 ) | 0;
            d = c;
            c = b;
            b = a;
            a = ( temp1 + temp2 ) | 0;
        }

        this.#h0 = ( this.#h0 + a ) | 0;
        this.#h1 = ( this.#h1 + b ) | 0;
        this.#h2 = ( this.#h2 + c ) | 0;
        this.#h3 = ( this.#h3 + d ) | 0;
        this.#h4 = ( this.#h4 + e ) | 0;
        this.#h5 = ( this.#h5 + f ) | 0;
        this.#h6 = ( this.#h6 + g ) | 0;
        this.#h7 = ( this.#h7 + h ) | 0;
    }

    update( str: string )
    {
        this.updateBytes( encodeUtf8( str ));
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

            for( let i = 0; i < toCopy; ++i )
            {
                this.#buffer[this.#bufLen + i] = bytes[offset + i];
            }

            this.#bufLen += toCopy;
            offset += toCopy;
            len -= toCopy;

            if( this.#bufLen === 64 )
            {
                this.#compress( this.#buffer, 0 );
                this.#bufLen = 0;
            }
        }

        while( len >= 64 )
        {
            this.#compress( bytes, offset );
            offset += 64;
            len -= 64;
        }

        if( len > 0 )
        {
            for( let i = 0; i < len; ++i )
            {
                this.#buffer[i] = bytes[offset + i];
            }

            this.#bufLen = len;
        }
    }

    digest(): Uint8Array
    {
        const s0 = this.#h0;
        const s1 = this.#h1;
        const s2 = this.#h2;
        const s3 = this.#h3;
        const s4 = this.#h4;
        const s5 = this.#h5;
        const s6 = this.#h6;
        const s7 = this.#h7;

        let padLen = this.#bufLen;

        for( let i = 0; i < padLen; ++i )
        {
            PAD_BLOCK[i] = this.#buffer[i];
        }

        PAD_BLOCK[padLen++] = 0x80;

        if( padLen > 56 )
        {
            PAD_BLOCK.fill( 0, padLen, 64 );
            this.#compress( PAD_BLOCK, 0 );
            PAD_BLOCK.fill( 0, 0, 56 );
        }
        else
        {
            PAD_BLOCK.fill( 0, padLen, 56 );
        }

        const totalBits = this.#totalLen * 8;
        const highBits = Math.floor( totalBits / 0x100000000 ) >>> 0;
        const lowBits = totalBits >>> 0;

        writeUint32BE( PAD_BLOCK, 56, highBits );
        writeUint32BE( PAD_BLOCK, 60, lowBits );

        this.#compress( PAD_BLOCK, 0 );

        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        const h5 = this.#h5;
        const h6 = this.#h6;
        const h7 = this.#h7;

        this.#h0 = s0;
        this.#h1 = s1;
        this.#h2 = s2;
        this.#h3 = s3;
        this.#h4 = s4;
        this.#h5 = s5;
        this.#h6 = s6;
        this.#h7 = s7;

        const byteLength = this.#bitLength / 8;
        const outBytes = new Uint8Array( byteLength );

        writeUint32BE( outBytes, 0, h0 );
        writeUint32BE( outBytes, 4, h1 );

        if( byteLength > 8 )
        {
            writeUint32BE( outBytes, 8, h2 );
        }

        if( byteLength > 12 )
        {
            writeUint32BE( outBytes, 12, h3 );
        }

        if( byteLength > 16 )
        {
            writeUint32BE( outBytes, 16, h4 );
            writeUint32BE( outBytes, 20, h5 );
        }

        if( byteLength > 24 )
        {
            writeUint32BE( outBytes, 24, h6 );
            writeUint32BE( outBytes, 28, h7 );
        }

        return outBytes;
    }
}
