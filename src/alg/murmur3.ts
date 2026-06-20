const ENCODER = new TextEncoder();

export default class MurmurHash3
{
    #states: { h1: number, h2: number, h3: number, h4: number }[];
    #buffer = new Uint8Array( 16 );
    #bufLen = 0;
    #totalLen = 0;
    #bitLength: 64 | 96 | 128 | 192 | 256;

    constructor( bitLength: 64 | 96 | 128 | 192 | 256 = 64 )
    {
        this.#bitLength = bitLength;

        const passes = Math.ceil( bitLength / 128 );
        this.#states = [];

        for( let i = 0; i < passes; ++i )
        {
            const seed = ( 0xdeadbeef ^ i ) >>> 0;

            this.#states.push({
                h1: seed,
                h2: seed,
                h3: seed,
                h4: seed
            });
        }
    }

    #mixBlock( b: Uint8Array, o: number )
    {
        let k1 = ( b[o] ) | ( b[o + 1] << 8 ) | ( b[o + 2] << 16 ) | ( b[o + 3] << 24 );
        let k2 = ( b[o + 4] ) | ( b[o + 5] << 8 ) | ( b[o + 6] << 16 ) | ( b[o + 7] << 24 );
        let k3 = ( b[o + 8] ) | ( b[o + 9] << 8 ) | ( b[o + 10] << 16 ) | ( b[o + 11] << 24 );
        let k4 = ( b[o + 12] ) | ( b[o + 13] << 8 ) | ( b[o + 14] << 16 ) | ( b[o + 15] << 24 );

        const c1 = 0x239b961b;
        const c2 = 0xab0e9789;
        const c3 = 0x38b34ae5;
        const c4 = 0xa1e38b93;

        for( let s = 0; s < this.#states.length; ++s )
        {
            const state = this.#states[s];
            let h1 = state.h1;
            let h2 = state.h2;
            let h3 = state.h3;
            let h4 = state.h4;

            let tk1 = Math.imul( k1, c1 );
            tk1 = ( tk1 << 15 ) | ( tk1 >>> 17 );
            tk1 = Math.imul( tk1, c2 );
            h1 ^= tk1;
            h1 = ( h1 << 19 ) | ( h1 >>> 13 );
            h1 = ( h1 + h2 ) | 0;
            h1 = ( Math.imul( h1, 5 ) + 0x561ccd1b ) | 0;

            let tk2 = Math.imul( k2, c2 );
            tk2 = ( tk2 << 16 ) | ( tk2 >>> 16 );
            tk2 = Math.imul( tk2, c3 );
            h2 ^= tk2;
            h2 = ( h2 << 17 ) | ( h2 >>> 15 );
            h2 = ( h2 + h3 ) | 0;
            h2 = ( Math.imul( h2, 5 ) + 0x0b0a747c ) | 0;

            let tk3 = Math.imul( k3, c3 );
            tk3 = ( tk3 << 17 ) | ( tk3 >>> 15 );
            tk3 = Math.imul( tk3, c4 );
            h3 ^= tk3;
            h3 = ( h3 << 15 ) | ( h3 >>> 17 );
            h3 = ( h3 + h4 ) | 0;
            h3 = ( Math.imul( h3, 5 ) + 0x3b2d11b7 ) | 0;

            let tk4 = Math.imul( k4, c4 );
            tk4 = ( tk4 << 18 ) | ( tk4 >>> 14 );
            tk4 = Math.imul( tk4, c1 );
            h4 ^= tk4;
            h4 = ( h4 << 13 ) | ( h4 >>> 19 );
            h4 = ( h4 + h1 ) | 0;
            h4 = ( Math.imul( h4, 5 ) + 0x85ebca6b ) | 0;

            state.h1 = h1;
            state.h2 = h2;
            state.h3 = h3;
            state.h4 = h4;
        }
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
            const needed = 16 - this.#bufLen;
            const toCopy = Math.min( needed, len );

            this.#buffer.set( bytes.subarray( offset, offset + toCopy ), this.#bufLen );
            this.#bufLen += toCopy;
            offset += toCopy;
            len -= toCopy;

            if( this.#bufLen === 16 )
            {
                this.#mixBlock( this.#buffer, 0 );
                this.#bufLen = 0;
            }
        }

        while( len >= 16 )
        {
            this.#mixBlock( bytes, offset );
            offset += 16;
            len -= 16;
        }

        if( len > 0 )
        {
            this.#buffer.set( bytes.subarray( offset, offset + len ), 0 );
            this.#bufLen = len;
        }
    }

    digest(): Uint8Array
    {
        const byteLength = this.#bitLength / 8;
        const bytes = new Uint8Array( byteLength );
        const view = new DataView( bytes.buffer );

        const c1 = 0x239b961b;
        const c2 = 0xab0e9789;
        const c3 = 0x38b34ae5;
        const c4 = 0xa1e38b93;

        const tailLen = this.#bufLen;
        const b = this.#buffer;
        const totalLen = this.#totalLen;

        for( let s = 0; s < this.#states.length; ++s )
        {
            const state = this.#states[s];
            let h1 = state.h1;
            let h2 = state.h2;
            let h3 = state.h3;
            let h4 = state.h4;

            let k1 = 0;
            let k2 = 0;
            let k3 = 0;
            let k4 = 0;

            if( tailLen >= 15 ){ k4 ^= b[14] << 16; }
            if( tailLen >= 14 ){ k4 ^= b[13] << 8; }
            if( tailLen >= 13 )
            {
                k4 ^= b[12];
                k4 = Math.imul( k4, c4 );
                k4 = ( k4 << 18 ) | ( k4 >>> 14 );
                k4 = Math.imul( k4, c1 );
                h4 ^= k4;
            }

            if( tailLen >= 12 ){ k3 ^= b[11] << 24; }
            if( tailLen >= 11 ){ k3 ^= b[10] << 16; }
            if( tailLen >= 10 ){ k3 ^= b[9] << 8; }
            if( tailLen >= 9 )
            {
                k3 ^= b[8];
                k3 = Math.imul( k3, c3 );
                k3 = ( k3 << 17 ) | ( k3 >>> 15 );
                k3 = Math.imul( k3, c4 );
                h3 ^= k3;
            }

            if( tailLen >= 8 ){ k2 ^= b[7] << 24; }
            if( tailLen >= 7 ){ k2 ^= b[6] << 16; }
            if( tailLen >= 6 ){ k2 ^= b[5] << 8; }
            if( tailLen >= 5 )
            {
                k2 ^= b[4];
                k2 = Math.imul( k2, c2 );
                k2 = ( k2 << 16 ) | ( k2 >>> 16 );
                k2 = Math.imul( k2, c3 );
                h2 ^= k2;
            }

            if( tailLen >= 4 ){ k1 ^= b[3] << 24; }
            if( tailLen >= 3 ){ k1 ^= b[2] << 16; }
            if( tailLen >= 2 ){ k1 ^= b[1] << 8; }
            if( tailLen >= 1 )
            {
                k1 ^= b[0];
                k1 = Math.imul( k1, c1 );
                k1 = ( k1 << 15 ) | ( k1 >>> 17 );
                k1 = Math.imul( k1, c2 );
                h1 ^= k1;
            }

            h1 ^= totalLen;
            h2 ^= totalLen;
            h3 ^= totalLen;
            h4 ^= totalLen;

            h1 = ( h1 + h2 ) | 0;
            h1 = ( h1 + h3 ) | 0;
            h1 = ( h1 + h4 ) | 0;
            h2 = ( h2 + h1 ) | 0;
            h3 = ( h3 + h1 ) | 0;
            h4 = ( h4 + h1 ) | 0;

            h1 ^= h1 >>> 16;
            h1 = Math.imul( h1, 0x85ebca6b );
            h1 ^= h1 >>> 13;
            h1 = Math.imul( h1, 0xc2b2ae35 );
            h1 ^= h1 >>> 16;

            h2 ^= h2 >>> 16;
            h2 = Math.imul( h2, 0x85ebca6b );
            h2 ^= h2 >>> 13;
            h2 = Math.imul( h2, 0xc2b2ae35 );
            h2 ^= h2 >>> 16;

            h3 ^= h3 >>> 16;
            h3 = Math.imul( h3, 0x85ebca6b );
            h3 ^= h3 >>> 13;
            h3 = Math.imul( h3, 0xc2b2ae35 );
            h3 ^= h3 >>> 16;

            h4 ^= h4 >>> 16;
            h4 = Math.imul( h4, 0x85ebca6b );
            h4 ^= h4 >>> 13;
            h4 = Math.imul( h4, 0xc2b2ae35 );
            h4 ^= h4 >>> 16;

            h1 = ( h1 + h2 ) | 0;
            h1 = ( h1 + h3 ) | 0;
            h1 = ( h1 + h4 ) | 0;
            h2 = ( h2 + h1 ) | 0;
            h3 = ( h3 + h1 ) | 0;
            h4 = ( h4 + h1 ) | 0;

            const offset = s * 16;

            if( offset < byteLength )
            {
                view.setUint32( offset, h1 >>> 0, false );
            }

            if( offset + 4 < byteLength )
            {
                view.setUint32( offset + 4, h2 >>> 0, false );
            }

            if( offset + 8 < byteLength )
            {
                view.setUint32( offset + 8, h3 >>> 0, false );
            }

            if( offset + 12 < byteLength )
            {
                view.setUint32( offset + 12, h4 >>> 0, false );
            }
        }

        return bytes;
    }
}
