declare const Buffer: any;

export function bytesToHex( bytes: Uint8Array ): string
{
    if( typeof Buffer === 'function' )
    {
        return Buffer.from( bytes ).toString( 'hex' );
    }

    let hex = '';

    for( let i = 0; i < bytes.length; ++i )
    {
        hex += bytes[i].toString( 16 ).padStart( 2, '0' );
    }

    return hex;
}


export function bytesToBase36( bytes: Uint8Array ): string
{
    const view = new DataView( bytes.buffer, bytes.byteOffset, bytes.byteLength );
    const results: string[] = [];
    let i = 0;

    for( ; i + 4 <= bytes.length; i += 4 )
    {
        const val = view.getUint32( i, false );

        results.push( val.toString( 36 ).padStart( 7, '0' ));
    }

    if( i < bytes.length )
    {
        let val = 0;
        const remaining = bytes.length - i;

        for( let j = 0; j < remaining; ++j )
        {
            val = ( val << 8 ) | bytes[i + j];
        }

        results.push( val.toString( 36 ).padStart( remaining * 2, '0' ));
    }

    return results.join( '' );
}


const BASE62_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

export function bytesToBase62( bytes: Uint8Array ): string
{
    const view = new DataView( bytes.buffer, bytes.byteOffset, bytes.byteLength );
    const results: string[] = [];
    let i = 0;

    for( ; i + 4 <= bytes.length; i += 4 )
    {
        let val = view.getUint32( i, false );
        let chunk = '';

        for( let j = 0; j < 6; ++j )
        {
            chunk = BASE62_CHARS[val % 62] + chunk;
            val = Math.floor( val / 62 );
        }

        results.push( chunk );
    }

    if( i < bytes.length )
    {
        let val = 0;
        const remaining = bytes.length - i;

        for( let j = 0; j < remaining; ++j )
        {
            val = ( val << 8 ) | bytes[i + j];
        }

        const padLen = remaining === 1 ? 2 : ( remaining === 2 ? 4 : 5 );
        let chunk = '';

        for( let j = 0; j < padLen; ++j )
        {
            chunk = BASE62_CHARS[val % 62] + chunk;
            val = Math.floor( val / 62 );
        }

        results.push( chunk );
    }

    return results.join( '' );
}


const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64( bytes: Uint8Array ): string
{
    if( typeof Buffer === 'function' )
    {
        return Buffer.from( bytes ).toString( 'base64' );
    }

    let result = '';
    let i = 0;
    const len = bytes.length;

    for( ; i + 3 <= len; i += 3 )
    {
        const val = ( bytes[i] << 16 ) | ( bytes[i + 1] << 8 ) | bytes[i + 2];

        result += BASE64_CHARS[( val >>> 18 ) & 63];
        result += BASE64_CHARS[( val >>> 12 ) & 63];
        result += BASE64_CHARS[( val >>> 6 ) & 63];
        result += BASE64_CHARS[val & 63];
    }

    if( i < len )
    {
        const remaining = len - i;

        if( remaining === 1 )
        {
            const val = bytes[i];

            result += BASE64_CHARS[( val >>> 2 ) & 63];
            result += BASE64_CHARS[( val << 4 ) & 63];
            result += '==';
        }

        if( remaining === 2 )
        {
            const val = ( bytes[i] << 8 ) | bytes[i + 1];

            result += BASE64_CHARS[( val >>> 10 ) & 63];
            result += BASE64_CHARS[( val >>> 4 ) & 63];
            result += BASE64_CHARS[( val << 2 ) & 63];
            result += '=';
        }
    }

    return result;
}


export function bytesToBase64Url( bytes: Uint8Array ): string
{
    if( typeof Buffer === 'function' )
    {
        return Buffer.from( bytes ).toString( 'base64url' );
    }

    const b64 = bytesToBase64( bytes );
    const url = b64.replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );

    return url;
}


export function encodeBytes( bytes: Uint8Array, encoding: 'hex' | 'base36' | 'base62' | 'base64' | 'base64url' = 'base36' ): string
{
    if( encoding === 'hex' ){ return bytesToHex( bytes ) }
    if( encoding === 'base64' ){ return bytesToBase64( bytes ) }
    if( encoding === 'base64url' ){ return bytesToBase64Url( bytes ) }
    if( encoding === 'base62' ){ return bytesToBase62( bytes ) }

    return bytesToBase36( bytes );
}
