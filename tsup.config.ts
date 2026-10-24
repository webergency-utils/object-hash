import { defineConfig } from 'tsup';

export default defineConfig({
    entry     : [ 'src/hash.ts' ],
    format    : [ 'cjs', 'esm' ],
    dts       : true,
    sourcemap : false,
    clean     : true,
    shims     : true,
    splitting : false,
    esbuildOptions( options )
    {
        options.minifyWhitespace = true;
        options.minifySyntax = true;
    }
});
