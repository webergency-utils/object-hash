export default class Cyrb64Hash
{
    #states: { h1: number, h2: number }[];
    #bitLength: 64 | 96 | 128 | 192 | 256;

    constructor( bitLength: 64 | 96 | 128 | 192 | 256 = 64 )
    {
        this.#bitLength = bitLength;

        const passes = Math.ceil( bitLength / 64 );
        this.#states = [];

        for( let i = 0; i < passes; ++i )
        {
            this.#states.push({
                h1: 0xdeadbeef ^ i,
                h2: 0x41c6ce57 ^ i
            });
        }
    }

    update( str: string )
    {
        const len = this.#states.length;
        const s0 = this.#states[0];
        const s1 = this.#states[1];
        const s2 = this.#states[2];
        const s3 = this.#states[3];

        let h1_0 = s0.h1;
        let h2_0 = s0.h2;
        let h1_1 = s1 ? s1.h1 : 0;
        let h2_1 = s1 ? s1.h2 : 0;
        let h1_2 = s2 ? s2.h1 : 0;
        let h2_2 = s2 ? s2.h2 : 0;
        let h1_3 = s3 ? s3.h1 : 0;
        let h2_3 = s3 ? s3.h2 : 0;

        for( let i = 0, ch; i < str.length; ++i )
        {
            ch = str.charCodeAt( i );
            h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
            h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );

            if( len > 1 )
            {
                h1_1 = Math.imul( h1_1 ^ ch, 2654435761 );
                h2_1 = Math.imul( h2_1 ^ ch, 1597334677 );
            }

            if( len > 2 )
            {
                h1_2 = Math.imul( h1_2 ^ ch, 2654435761 );
                h2_2 = Math.imul( h2_2 ^ ch, 1597334677 );
            }

            if( len > 3 )
            {
                h1_3 = Math.imul( h1_3 ^ ch, 2654435761 );
                h2_3 = Math.imul( h2_3 ^ ch, 1597334677 );
            }
        }

        s0.h1 = h1_0;
        s0.h2 = h2_0;

        if( len > 1 )
        {
            s1.h1 = h1_1;
            s1.h2 = h2_1;
        }

        if( len > 2 )
        {
            s2.h1 = h1_2;
            s2.h2 = h2_2;
        }

        if( len > 3 )
        {
            s3.h1 = h1_3;
            s3.h2 = h2_3;
        }
    }

    updateBytes( bytes: Uint8Array )
    {
        const len = this.#states.length;
        const s0 = this.#states[0];
        const s1 = this.#states[1];
        const s2 = this.#states[2];
        const s3 = this.#states[3];

        let h1_0 = s0.h1;
        let h2_0 = s0.h2;
        let h1_1 = s1 ? s1.h1 : 0;
        let h2_1 = s1 ? s1.h2 : 0;
        let h1_2 = s2 ? s2.h1 : 0;
        let h2_2 = s2 ? s2.h2 : 0;
        let h1_3 = s3 ? s3.h1 : 0;
        let h2_3 = s3 ? s3.h2 : 0;

        for( let i = 0, ch; i < bytes.length; ++i )
        {
            ch = bytes[i];
            h1_0 = Math.imul( h1_0 ^ ch, 2654435761 );
            h2_0 = Math.imul( h2_0 ^ ch, 1597334677 );

            if( len > 1 )
            {
                h1_1 = Math.imul( h1_1 ^ ch, 2654435761 );
                h2_1 = Math.imul( h2_1 ^ ch, 1597334677 );
            }

            if( len > 2 )
            {
                h1_2 = Math.imul( h1_2 ^ ch, 2654435761 );
                h2_2 = Math.imul( h2_2 ^ ch, 1597334677 );
            }

            if( len > 3 )
            {
                h1_3 = Math.imul( h1_3 ^ ch, 2654435761 );
                h2_3 = Math.imul( h2_3 ^ ch, 1597334677 );
            }
        }

        s0.h1 = h1_0;
        s0.h2 = h2_0;

        if( len > 1 )
        {
            s1.h1 = h1_1;
            s1.h2 = h2_1;
        }

        if( len > 2 )
        {
            s2.h1 = h1_2;
            s2.h2 = h2_2;
        }

        if( len > 3 )
        {
            s3.h1 = h1_3;
            s3.h2 = h2_3;
        }
    }

    digest(): Uint8Array
    {
        const byteLength = this.#bitLength / 8;
        const bytes = new Uint8Array( byteLength );
        const view = new DataView( bytes.buffer );

        for( let s = 0; s < this.#states.length; ++s )
        {
            const state = this.#states[s];
            let h1 = state.h1;
            let h2 = state.h2;

            h1  = Math.imul( h1 ^ ( h1 >>> 16 ), 2246822507 );
            h1 ^= Math.imul( h2 ^ ( h2 >>> 13 ), 3266489909 );
            h2  = Math.imul( h2 ^ ( h2 >>> 16 ), 2246822507 );
            h2 ^= Math.imul( h1 ^ ( h1 >>> 13 ), 3266489909 );

            const u2 = h2 >>> 0;
            const u1 = h1 >>> 0;

            const offset = s * 8;

            if( offset < byteLength )
            {
                view.setUint32( offset, u2, false );
            }

            if( offset + 4 < byteLength )
            {
                view.setUint32( offset + 4, u1, false );
            }
        }

        return bytes;
    }
}
